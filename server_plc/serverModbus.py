import os
import sys
import json
import math
import random
import asyncio
import logging

# Assicura la risoluzione dei moduli locali (custom_pdu, llm_client) indipendentemente dalla directory di lancio
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from pymodbus.server import ModbusTcpServer
from pymodbus.simulator import SimData, SimDevice, DataType
from pymodbus import ModbusDeviceIdentification
from custom_pdu import get_custom_pdus

# Caricamento obbligatorio del file di configurazione (nessun fallback)
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_config.json")
if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(f"File di configurazione obbligatorio '{CONFIG_PATH}' non trovato.")

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

cfg_network = CONFIG["network"]
cfg_identity = CONFIG["device_identity"]
cfg_memory = CONFIG["modbus_memory"]
cfg_physics = CONFIG["physical_simulation"]

# Inizializzazione del logger
log_level = getattr(logging, cfg_network["log_level"].upper(), logging.INFO)
logging.basicConfig(level=log_level)
_logger = logging.getLogger(__name__)

# Valori iniziali per i registri letti da config
hr_values = [0] * cfg_memory["num_holding_registers"]
for addr_str, val in cfg_memory.get("initial_holding_registers", {}).items():
    hr_values[int(addr_str)] = val

ir_values = [0] * cfg_memory["num_input_registers"]
for addr_str, val in cfg_memory.get("initial_input_registers", {}).items():
    ir_values[int(addr_str)] = val

co_values = [False] * cfg_memory["num_coils"]
for addr_str, val in cfg_memory.get("initial_coils", {}).items():
    co_values[int(addr_str)] = bool(val)

di_values = [False] * cfg_memory["num_discrete_inputs"]
for addr_str, val in cfg_memory.get("initial_discrete_inputs", {}).items():
    di_values[int(addr_str)] = bool(val)

# Definizione dei blocchi dati con SimData
hr_block = SimData(0, values=hr_values, datatype=DataType.REGISTERS)  # Holding Registers
ir_block = SimData(0, values=ir_values, datatype=DataType.REGISTERS)  # Input Registers
co_block = SimData(0, values=co_values, datatype=DataType.BITS)       # Coils
di_block = SimData(0, values=di_values, datatype=DataType.BITS)       # Discrete Inputs

# SimDevice con simdata come tupla (di, co, hr, ir)
device = SimDevice(id=cfg_network["device_id"], simdata=([di_block], [co_block], [hr_block], [ir_block]))

# Riferimenti alle liste di registri runtime
# Queste sono le liste effettive utilizzate dal server per leggere/scrivere
_runtime_hr = None  # Holding Registers runtime
_runtime_ir = None  # Input Registers runtime


async def physical_process_sp():
    """
    Simulazione fisica del processo a primo ordine (PT1) con transiente realistico.
    Tutti i parametri provengono direttamente da server_config.json.
    """
    _logger.info("Simulazione processo fisico (modello PT1)...")

    # Parametri estratti dal file di configurazione
    sp_addr = cfg_physics["sp_register_address"]
    pv_addr = cfg_physics["pv_register_address"]
    TAU = cfg_physics["tau"]
    SP_CRIT = cfg_physics["sp_crit"]
    V_NOMINAL = cfg_physics["v_nominal"]
    K_DEFICIT = cfg_physics["k_deficit"]
    OSC_AMP_INIT = cfg_physics["osc_amp_init"]
    OSC_AMP_GROWTH = cfg_physics["osc_amp_growth"]
    OSC_AMP_SCALE = cfg_physics["osc_amp_scale"]
    OSC_FREQ = cfg_physics["osc_freq"]
    SENSOR_NOISE_STD = cfg_physics["sensor_noise_std"]
    INSTABILITY_NOISE_STD = cfg_physics["instability_noise_std"]
    DT = cfg_physics["dt"]
    CLAMP_MIN = cfg_physics["clamp_min"]
    CLAMP_MAX = cfg_physics["clamp_max"]

    # Stato interno del processo: valore corrente del vapore
    V_current = float(_runtime_ir[pv_addr])
    # Timer di instabilità: quanti secondi siamo sotto SP_CRIT
    instability_time = 0.0
    # Contatore di tempo assoluto per il calcolo delle fasi sinusoidali
    t_abs = 0.0
    prev_sp = None

    while True:
        set_point = _runtime_hr[sp_addr]
        t_abs += DT

        if prev_sp is not None and prev_sp != set_point:
            if set_point < SP_CRIT and prev_sp >= SP_CRIT:
                _logger.warning(f"Rilevato Set-Point anomalo (SP={set_point} < {SP_CRIT}): innesco instabilità e cavitazione.")
            elif set_point >= SP_CRIT and prev_sp < SP_CRIT:
                _logger.info(f"Set-Point ripristinato (SP={set_point} >= {SP_CRIT}): convergenza a regime nominale.")
        prev_sp = set_point

        if set_point >= SP_CRIT:
            # ---- FASE STABILE ----
            # Il target è il valore nominale; il sistema converge con PT1
            V_target = V_NOMINAL
            instability_time = 0.0  # reset del timer di instabilità

            # Integrazione Eulero in avanti:  V += (V_target - V) * DT / tau  +  ε
            dV = (V_target - V_current) * DT / TAU
            noise = random.gauss(0, SENSOR_NOISE_STD)
            V_current += dV + noise

        else:
            # ---- FASE INSTABILE (SP < SP_CRIT) ----
            instability_time += DT
            sp_deficit = SP_CRIT - set_point  # > 0 quando instabile

            # Il target nominale scende proporzionalmente al deficit di SP
            V_target_base = V_NOMINAL - K_DEFICIT * sp_deficit

            # L'ampiezza cresce con il tempo ma satura a un limite proporzionale al deficit di SP
            osc_amp_max = OSC_AMP_SCALE * sp_deficit
            osc_amplitude = min(OSC_AMP_INIT + OSC_AMP_GROWTH * instability_time, osc_amp_max)

            # Oscillazione sinusoidale sovrapposta al target calante
            oscillation = osc_amplitude * math.sin(2 * math.pi * OSC_FREQ * t_abs)

            V_target = V_target_base + oscillation

            # Rumore più elevato per turbolenza/cavitazione
            noise = random.gauss(0, INSTABILITY_NOISE_STD)

            # Integrazione PT1: il processo ha inerzia, non salta di colpo
            dV = (V_target - V_current) * DT / TAU
            V_current += dV + noise

            _logger.debug(
                f"SP anomalo ({set_point}): instab_t={instability_time:.1f}s, "
                f"V_target={V_target:.0f}, V_current={V_current:.0f}, "
                f"osc_amp={osc_amplitude:.1f}"
            )

        # Clamp fisico configurabile
        V_current = max(CLAMP_MIN, min(CLAMP_MAX, V_current))

        # Scrivo il valore intero nell'input register
        _runtime_ir[pv_addr] = int(round(V_current))
        await asyncio.sleep(DT)


def trace_packet_handler(sending: bool, data: bytes) -> bytes:
    # Logga i pacchetti con MBAP malformato per scopi di monitoraggio (calcolare latenza di scarto)
    # Un PLC reale scarta i pacchetti con PID != 0 (non sono Modbus TCP validi)
    if not sending and len(data) >= 7:
        pid = int.from_bytes(data[2:4], "big")
        if pid != 0:
            _logger.warning(f"Pacchetto con PID non valido ({pid}) ignorato dal framer. Dati: {data.hex()}")
    return data


async def run_server():
    global _runtime_hr, _runtime_ir

    _logger.info("Inizializzazione Honeypot Modbus...")
    _logger.info(f"Avvio del server TCP asincrono su {cfg_network['host']}:{cfg_network['port']}...")

    # Configurazione dell'identità del dispositivo da file JSON
    identity = ModbusDeviceIdentification(
        info_name={
            "VendorName": cfg_identity["vendor_name"],
            "ProductCode": cfg_identity["product_code"],
            "VendorUrl": cfg_identity["vendor_url"],
            "ProductName": cfg_identity["product_name"],
            "ModelName": cfg_identity["model_name"],
            "MajorMinorRevision": cfg_identity["firmware_revision"],
        }
    )

    # Costruzione del server TCP asincrono
    server = ModbusTcpServer(
        context=device,
        address=(cfg_network["host"], cfg_network["port"]),
        identity=identity,
        custom_pdu=get_custom_pdus(),
        trace_packet=trace_packet_handler
    )

    # Accediamo alle liste runtime dei registri DOPO la costruzione del server
    runtime = server.context.devices[cfg_network["device_id"]]
    _runtime_hr = runtime.block["h"][2]  # Lista registri Holding
    _runtime_ir = runtime.block["i"][2]  # Lista registri Input

    _logger.info(f"Runtime HR[{cfg_physics['sp_register_address']}] = {_runtime_hr[cfg_physics['sp_register_address']]}, "
                 f"IR[{cfg_physics['pv_register_address']}] = {_runtime_ir[cfg_physics['pv_register_address']]}")

    # Avvio simulazione processo fisico solo se abilitata
    physics_task = None
    if cfg_physics.get("enabled", True):
        physics_task = asyncio.create_task(physical_process_sp())

    try:
        await server.serve_forever()
    finally:
        if physics_task and not physics_task.done():
            physics_task.cancel()
            try:
                await physics_task
            except asyncio.CancelledError:
                pass
        try:
            await server.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    if sys.platform == "win32":
        # Evita 'RuntimeError: Event loop is closed' sul proactor di Windows al Ctrl+C
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        _logger.info("Server fermato dall'utente.")
