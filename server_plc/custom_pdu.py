import os
import sys
import json
import logging
import struct

# Assicura la corretta risoluzione dei moduli locali indipendentemente dalla CWD
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from pymodbus.constants import ExcCodes, ModbusStatus
from pymodbus.pdu import ModbusPDU
from pymodbus.pdu.bit_message import (
    ReadCoilsRequest,
    ReadDiscreteInputsRequest,
    WriteMultipleCoilsRequest,
    WriteSingleCoilRequest,
)
from pymodbus.pdu.exceptionresponse import ExceptionResponse
from pymodbus.pdu.register_message import (
    MaskWriteRegisterRequest,
    ReadHoldingRegistersRequest,
    ReadInputRegistersRequest,
    ReadWriteMultipleRegistersRequest,
    WriteMultipleRegistersRequest,
    WriteSingleRegisterRequest,
)
from pymodbus.pdu.utils import unpack_bitstring
from llm_client import llm_client

_logger = logging.getLogger(__name__)

# Caricamento obbligatorio del file di configurazione
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_config.json")
if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(f"File di configurazione obbligatorio '{CONFIG_PATH}' non trovato.")

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    _CONFIG = json.load(f)

# Function codes supportati standard da pymodbus 3.14
STANDARD_FCS = [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 16, 17, 20, 21, 22, 23, 24, 43]

# Limiti di dimensione per ciascun banco di memoria letti da server_config.json
NUM_HOLDING_REGISTERS = _CONFIG["modbus_memory"].get("num_holding_registers", 40)
NUM_INPUT_REGISTERS = _CONFIG["modbus_memory"].get("num_input_registers", 40)
NUM_COILS = _CONFIG["modbus_memory"].get("num_coils", 40)
NUM_DISCRETE_INPUTS = _CONFIG["modbus_memory"].get("num_discrete_inputs", 40)
REGISTER_COUNT = NUM_HOLDING_REGISTERS  # Mantenuto per retrocompatibilità

# > indica di leggere in big endian (sx to dx)
# H indica di leggere 2 byte
# B indica di leggere 1 byte

def _illegal_value(function_code: int) -> ExceptionResponse:
    # Risposta standard per richiesta malformata (ad esempio payload con lunghezza errata)
    return ExceptionResponse(function_code, ExcCodes.ILLEGAL_VALUE)
    # La richiesta viene rifiutata con codice 03 (illegal data value)
class _ValidatedReadRequest:
    # Validazione delle richieste di lettura 
    # Tutte le richieste di lettura (FC01, 02, 03, 04) hanno payload di 4 byte (2 indirizzo di partenza, 2 quantità)
    max_count = 0
    register_limit = REGISTER_COUNT

    def decode(self, data: bytes) -> None: # Intercetta il pacchetto prima di pymodbus
        self._malformed = len(data) != 4 # Se la lunghezza non è 4, il pacchetto è malformato
        if self._malformed:
            self.address = 0
            self.count = 0
            return
        self.address, self.count = struct.unpack(">HH", data) # Estrae indirizzo e quantità utilizzando big endian

    async def datastore_update(self, context, device_id): # Il server legge dal datastore
        if self._malformed or not 1 <= self.count <= self.max_count:
            return _illegal_value(self.function_code)
        # Limita gli accessi alla dimensione effettiva del banco di memoria
        if self.address + self.count > self.register_limit:
            return ExceptionResponse(self.function_code, ExcCodes.ILLEGAL_ADDRESS)
        return await super().datastore_update(context, device_id)


class ValidatedReadCoilsRequest(_ValidatedReadRequest, ReadCoilsRequest):
    max_count = 2000
    register_limit = NUM_COILS


class ValidatedReadDiscreteInputsRequest(_ValidatedReadRequest, ReadDiscreteInputsRequest):
    max_count = 2000
    register_limit = NUM_DISCRETE_INPUTS


class ValidatedReadHoldingRegistersRequest(_ValidatedReadRequest, ReadHoldingRegistersRequest):
    max_count = 125
    register_limit = NUM_HOLDING_REGISTERS


class ValidatedReadInputRegistersRequest(_ValidatedReadRequest, ReadInputRegistersRequest):
    max_count = 125
    register_limit = NUM_INPUT_REGISTERS


class _ValidatedFixedLengthRequest:
    payload_length = 0
    register_limit = NUM_HOLDING_REGISTERS

    def decode(self, data: bytes) -> None:
        self._malformed = len(data) != self.payload_length
        if self._malformed:
            self.address = 0
            return
        super().decode(data)

    async def datastore_update(self, context, device_id):
        if self._malformed:
            return _illegal_value(self.function_code)
        if self.address >= self.register_limit:
            return ExceptionResponse(self.function_code, ExcCodes.ILLEGAL_ADDRESS)
        return await super().datastore_update(context, device_id)


class ValidatedWriteSingleCoilRequest(WriteSingleCoilRequest):
    register_limit = NUM_COILS

    def decode(self, data: bytes) -> None:
        self._malformed = len(data) != 4
        self.address = 0
        self._raw_coil_value = None
        self.bits = []
        if self._malformed:
            return
        self.address, self._raw_coil_value = struct.unpack(">HH", data)
        self.bits = [self._raw_coil_value == ModbusStatus.ON]

    async def datastore_update(self, context, device_id):
        if self._malformed or self._raw_coil_value not in (ModbusStatus.OFF, ModbusStatus.ON):
            return _illegal_value(self.function_code)
        if self.address >= self.register_limit:
            return ExceptionResponse(self.function_code, ExcCodes.ILLEGAL_ADDRESS)
        return await super().datastore_update(context, device_id)


class ValidatedWriteSingleRegisterRequest(_ValidatedFixedLengthRequest, WriteSingleRegisterRequest):
    # FC 06 ha un payload fisso di 4 byte (utilizzo il mio metodo di validazione)

    payload_length = 4

class ValidatedWriteMultipleCoilsRequest(WriteMultipleCoilsRequest):
    # FC 15 validazione quantità, byte count e dimensione payload 
    # A differenza di single coil request, questo scrive più bit contemporaneamente
    # L'header è di 5 byte fissi (2 indirizzo, 2 quantità e 1 byte count per quanto è lungo il payload)
    # Payload contenente gli 0 e 1 da scrivere

    def decode(self, data: bytes) -> None:
        self._malformed = len(data) < 5 # Se il pacchetto è più corto di 5 byte (lunghezza header) è malformato
        self.address = 0
        self.count = 0
        self._byte_count = 0
        self.bits = []
        if self._malformed:
            return
        self.address, self.count, self._byte_count = struct.unpack(">HHB", data[:5]) # Estraiamo indirizzo, quantità e byte count (big endian)
        payload = data[5:] # Il payload lo prendo da dopo l'header fino alla fine
        self._malformed = (
            not 1 <= self.count <= 1968 # Modbus permette di scrivere massimo 1968 coils alla volta
            or self._byte_count != (self.count + 7) // 8 # calcola il numero di byte per scrivere i coil e lo confronta col byte count del payload
            # (i coil sono bit e vengono impacchettati a gruppi di 8 dentro un singolo byte)
            or len(payload) != self._byte_count # Controllo se la lunghezza del payload corrisponde
        )
        if not self._malformed:
            self.bits = unpack_bitstring(payload)[:self.count] # spacchettamento del payload per avere i singoli bit (coil) da scrivere

    async def datastore_update(self, context, device_id):
        if self._malformed: 
            return _illegal_value(self.function_code)
        if self.address + self.count > NUM_COILS:
            return ExceptionResponse(self.function_code, ExcCodes.ILLEGAL_ADDRESS)
        return await super().datastore_update(context, device_id)


class ValidatedWriteMultipleRegistersRequest(WriteMultipleRegistersRequest):
    # FC 16 (write multiple registers) è sostanzialmente identico a FC 15 con coil ma lavora con i registri (16 bit) invece che con i bit
    # L'header è sempre fisso a 5 byte

    def decode(self, data: bytes) -> None:
        self._malformed = len(data) < 5
        self.address = 0
        self.count = 0
        self._byte_count = 0
        self.registers = []
        if self._malformed:
            return
        self.address, self.count, self._byte_count = struct.unpack(">HHB", data[:5])
        payload = data[5:]
        self._malformed = (
            not 1 <= self.count <= 123 # Modbus consente 123 registri alla volta questo perchè ogni registro è 2 byte quindi di più poi si violerebbe il limite fisico del pacchetto
            or self._byte_count != self.count * 2 # Calcola il numero di byte per scrivere i registri e lo confronta col byte count del payload
            or len(payload) != self._byte_count # Controllo se la lunghezza del payload corrisponde
        )
        if not self._malformed:
            self.registers = [
                struct.unpack(">H", payload[offset : offset + 2])[0] # spacchettamento del payload per avere i singoli registri (big endian)
                for offset in range(0, len(payload), 2) # itera sul payload prendendo 2 byte alla volta
            ]

    async def datastore_update(self, context, device_id):
        if self._malformed:
            return _illegal_value(self.function_code)
        if self.address + self.count > NUM_HOLDING_REGISTERS:
            return ExceptionResponse(self.function_code, ExcCodes.ILLEGAL_ADDRESS)
        return await super().datastore_update(context, device_id)

class ValidatedMaskWriteRegisterRequest(_ValidatedFixedLengthRequest, MaskWriteRegisterRequest):
    # FC 22 ha un payload fisso di 6 byte

    payload_length = 6

class ValidatedReadWriteMultipleRegistersRequest(ReadWriteMultipleRegistersRequest):
    # FC 23 legge e scrive contemporaneamente su registri multipli (read/write)
    # Header di 9 byte (2 indirizzo lettura, 2 quantità lettura, 2 indirizzo scrittura, 2 quantità scrittura, 1 byte count scrittura)
    # Uguale a FC 16 ma legge anche dei registri
    # La richiesta contiene i dati che si vogliono scrivere mentre i dati per la lettura occupano 4 byte nell'header
    # La risposta contiene i dati letti 

    def decode(self, data: bytes) -> None:
        self._malformed = len(data) < 9
        self.read_address = 0
        self.read_count = 0
        self.write_address = 0
        self.write_count = 0
        self.write_byte_count = 0
        self.write_registers = []
        if self._malformed:
            return
        (
            self.read_address,
            self.read_count,
            self.write_address,
            self.write_count,
            self.write_byte_count,
        ) = struct.unpack(">HHHHB", data[:9])
        payload = data[9:]
        self._malformed = (
            not 1 <= self.read_count <= 125 # Per la parte di lettura il limite max è di 125 registri
            or not 1 <= self.write_count <= 121 # Per la parte di scrittura il limite max è di 121 registri
            # Come mai non 123 come prima? Perchè stavolta l'header è più grande (9 byte)
            or self.write_byte_count != self.write_count * 2 # Controllo byte count scrittura
            or len(payload) != self.write_byte_count # Controllo se la lunghezza del payload è corretta
        )
        if not self._malformed:
            self.write_registers = [
                struct.unpack(">H", payload[offset : offset + 2])[0]
                for offset in range(0, len(payload), 2) 
            ]

    async def datastore_update(self, context, device_id):
        if self._malformed:
            return _illegal_value(self.function_code)
        # FC 23 controlla entrambe le finestre (lettura e scrittura) con i loro attributi corretti
        if self.read_address + self.read_count > NUM_HOLDING_REGISTERS or self.write_address + self.write_count > NUM_HOLDING_REGISTERS:
            return ExceptionResponse(self.function_code, ExcCodes.ILLEGAL_ADDRESS)
        return await super().datastore_update(context, device_id)


class NoResponsePDU(ModbusPDU):
    # Dato che PyModBus deve sempre restituire una risposta di tipo ModbusPDU
    # Per il caso in cui si decide di non fare nulla, prendiamo l'oggetto PDU e lo modifico in modo che venga restituito False
    # Quando pymodbus elaborerà la richiesta e prenderà questa risposta vedrà l'oggetto false e non invierà nulla

    def __bool__(self) -> bool:
        return False


class CatchAllPDU(ModbusPDU): # PDU che cattura function code non gestiti da pymodbus

    function_code = -1 # Qua è dove viene salvato l'FC non gestito 

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.raw_data = b""
        self.response_data = b""
    
    def decode(self, data: bytes) -> None:
        # Salva i dati grezzi ricevuti (dopo il function code)
        # Essendo un FC sconosciuto non sappiamo a priori come è strutturato il payload
        self.raw_data = data 
        self.response_data = b""
    
    def encode(self) -> bytes: 
        # Restituisce i dati della risposta generata
        return self.response_data
    
    async def datastore_update(self, context, dev_id):
        # raw_data contiene il payload dopo il FC (già separato da pymodbus)
        _logger.info(f"Ricevuto FC non supportato {self.function_code}. Interrogazione LLM...")

        # Invio dati all'LLM per generare la risposta
        # Inviamo FC + Payload separati questo perchè pymodbus riceve il pacchetto e prende subito il primo byte come FC
        response_bytes = await llm_client.generate_modbus_response(self.raw_data, self.function_code)

        if response_bytes:
            self.function_code = response_bytes[0] # Salvo il primo byte come FC
            self.response_data = response_bytes[1:] # Salvo il resto come Payload
        else:
            # action "ignore": nessuna risposta da parte dell'LLM
            return NoResponsePDU()

        return self

def get_custom_pdus() -> list[type[ModbusPDU]]:
    # Passo il dizionario con le mie classi modificate con validazione
    custom_classes = [
        ValidatedReadCoilsRequest,
        ValidatedReadDiscreteInputsRequest,
        ValidatedReadHoldingRegistersRequest,
        ValidatedReadInputRegistersRequest,
        ValidatedWriteSingleCoilRequest,
        ValidatedWriteSingleRegisterRequest,
        ValidatedWriteMultipleCoilsRequest,
        ValidatedWriteMultipleRegistersRequest,
        ValidatedMaskWriteRegisterRequest,
        ValidatedReadWriteMultipleRegistersRequest,
    ]

    # Genera una classe CatchAllPDU per ogni FC non standard
    # Pymodbus richiede che ogni singolo FC abbia una classe distinta
    for fc in range(0, 128):
        if fc not in STANDARD_FCS:
            # Creo la classe dinamica per il FC specifico
            cls = type(f"CatchAllFC{fc}", (CatchAllPDU,), {"function_code": fc})
            custom_classes.append(cls)
    return custom_classes
