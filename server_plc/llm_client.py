import os
import json
import time
import asyncio
import logging
from groq import AsyncGroq, RateLimitError
from dotenv import load_dotenv

# Carica le variabili d'ambiente dal file .env nella root
dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env')
load_dotenv(dotenv_path)

_logger = logging.getLogger(__name__)

# Caricamento obbligatorio del file di configurazione (nessun fallback)
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_config.json")
if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(f"File di configurazione obbligatorio '{CONFIG_PATH}' non trovato.")

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    _CONFIG = json.load(f)

cfg_identity = _CONFIG["device_identity"]
cfg_llm = _CONFIG["llm"]

# Client asincrono Groq
api_key = os.getenv("GROQ_API_KEY")
_groq_client = AsyncGroq(api_key=api_key) if api_key else None
if not api_key:
    _logger.warning("GROQ_API_KEY non configurata. LLM_Client disabilitato.")

# Modello LLM letto da server_config.json
GROQ_MODEL = cfg_llm["model"]

MAX_MODBUS_PDU_SIZE = 253
MAX_RESPONSE_DATA_BYTES = MAX_MODBUS_PDU_SIZE - 1
VALID_EXCEPTION_CODES = {1, 2, 3, 4} 
# 1 ILLEGAL FUNCTION, 2 ILLEGAL DATA ADDRESS, 3 ILLEGAL DATA VALUE, 4 SLAVE DEVICE FAILURE
# Sono le eccezioni di base che tutti i dispositivi Modbus devono supportare, inoltre le altre eccezioni sono molto più specifiche

# La scelta di utilizzare uno schema JSON e non chiedere all'LLM direttamente i byte in HEX è perchè il più delle volte non genererebbe solo i byte perciò dovremmo fare pulizia,
# inoltre abbiamo una sicurezza sul tipo di dato infatti con il json schema vincoliamo l'output a queste regole

MODBUS_RESPONSE_SCHEMA = {
    "name": "modbus_response",
    "strict": True, # strict=True: output must match the JSON schema exactly
    "schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["exception", "respond", "ignore"],
                "description": "exception: Modbus exception; respond: normal response; ignore: no reply"
            },
            "exception_code": {
                "anyOf": [
                    {"type": "integer", "enum": sorted(VALID_EXCEPTION_CODES)},
                    {"type": "null"}
                ],
                "description": "Modbus exception code (1-4). Required if action=exception, else null."
            },
            "response_data": {
                "anyOf": [
                    {
                        "type": "array",
                        "items": {"type": "integer", "minimum": 0, "maximum": 255},
                        "maxItems": MAX_RESPONSE_DATA_BYTES
                    },
                    {"type": "null"}
                ],
                "description": "Response payload bytes (0-255), excluding the leading FC byte. Required if action=respond, else null."
            },
            "reason": {
                "anyOf": [{"type": "string"}, {"type": "null"}],
                "description": "Brief rationale for the chosen action (optional)."
            }
        },
        "required": ["action", "exception_code", "response_data", "reason"],
        "additionalProperties": False
    }
}

def _build_response_bytes(fc: int, llm_json: dict) -> bytes:
    # Ricostruisce i byte della PDU Modbus dalla decisione JSON dell'LLM
    # action "exception" => FC|0x80 + exception_code
    # action "respond" => FC + response_data bytes
    # action "ignore" => b"" (nessuna risposta)
    # qualsiasi errore => eccezione ILLEGAL_FUNCTION (fallback)
    action = llm_json.get("action", "exception") 
    exception_code = llm_json.get("exception_code")
    response_data = llm_json.get("response_data")

    if action == "exception":
        # Faccio ulteriori controlli nonostante il json schema
        if response_data is not None or type(exception_code) is not int: 
            raise ValueError("risposta exception incompleta o incoerente")
        if exception_code not in VALID_EXCEPTION_CODES:
            raise ValueError(f"exception code Modbus non valido: {exception_code}")
        return bytes([fc | 0x80, exception_code])
        # In Modbus se c'è un errore prende il FC originale e ne accende il bit più significativo (in un byte equivale a 0x80 HEX)
        # Facendo fc | 0x80 stiamo facendo l'or bit a bit

    if action == "respond":
        if exception_code is not None or not isinstance(response_data, list):
            raise ValueError("risposta normale incompleta o incoerente")
        if len(response_data) > MAX_RESPONSE_DATA_BYTES:
            raise ValueError("risposta LLM oltre il limite PDU Modbus")
        if any(type(byte) is not int or not 0 <= byte <= 0xFF for byte in response_data):
            raise ValueError("response_data contiene un valore che non è un byte")
        data_bytes = bytes(response_data)
        return bytes([fc]) + data_bytes

    if action == "ignore":
        if exception_code is not None or response_data is not None:
            raise ValueError("azione ignore con dati di risposta")
        return b""

    raise ValueError(f"action sconosciuta: {action!r}")


class LLMClient:
    # Client per interrogare Groq LLM sui Function Code non gestiti da pymodbus.

    def __init__(self):
        self.client = _groq_client

    async def generate_modbus_response(self, raw_data: bytes, function_code: int) -> bytes:
        # Parametri:
        # raw_data: bytes Dati della PDU dopo il function code (payload grezzo)
        # function_code: int Function code della richiesta
        # Ritorna:
        # bytes: PDU di risposta completa (FC + payload), pronta per essere serializzata da pymodbus
        # Stringa vuota: nessuna risposta

        if not self.client:
            _logger.error("Chiamata LLM fallita: API Key non configurata.")
            return bytes([function_code | 0x80, 0x01])

        # Tronca il payload alla lunghezza massima ammissibile dalla PDU Modbus (252 byte) per sicurezza
        # 252 perché il massimo è 253 ma va tolto 1 byte per il function code
        raw_data = raw_data[:252] if raw_data else b""
        payload_hex = raw_data.hex(" ") if raw_data else "(empty)"
        payload_len = len(raw_data)

        desc = cfg_identity.get('description', f"{cfg_identity['vendor_name']} {cfg_identity['model_name']} industrial PLC.")
        system_prompt = (
            f"You are the firmware of a {cfg_identity['vendor_name']} {cfg_identity['model_name']} "
            f"({cfg_identity['firmware_revision']}). {desc}\n\n"
            "You received a Modbus TCP request whose Function Code is NOT handled "
            "by your standard runtime. Decide how to respond using:\n\n"
            "1. MODBUS SPEC (v1.1b3) — FC ranges:\n"
            "   - 1-64: public (some reserved/unassigned)\n"
            "   - 65-72, 100-110: user-defined (vendor extensions)\n"
            "   - 73-99, 111-127: reserved by Modbus.org\n"
            "   - >=128: invalid as request\n\n"
            "2. YOUR HARDWARE PROFILE (determines which vendor extensions you support)\n\n"
            "Actions:\n"
            "- exception: FC unsupported/reserved. Pick the appropriate code: "
            "1=IllegalFunction, 2=IllegalDataAddress, 3=IllegalDataValue, 4=ServerDeviceFailure\n"
            "- respond: FC is user-defined and plausible for your hardware; provide response bytes\n"
            "- ignore: drop without reply (rare)\n\n"
            "Fill 'reason' with one concise sentence explaining your decision."
        )

        user_prompt = (
            f"FC: {function_code} (0x{function_code:02X})\n"
            f"Payload: {payload_len} bytes — {payload_hex}\n\n"
            "How should this device handle this request?"
        )

        # System prompt è il contesto permanente che imposta la personalità e le regole
        # User prompt sono le informazioni specifiche della richiesta (cambia ad ogni chiamata)

        _logger.debug(f"Interrogo LLM per FC={function_code}, payload={payload_hex}")

        # Valori di fallback se l'LLM restituisce un errore il server risponderà con un "ILLEGAL_FUNCTION"
        response_bytes = bytes([function_code | 0x80, 0x01]) # Codice d'errore 1 (0x01)
        action_log = "errore_sconosciuto"
        exc_code_log = 1
        resp_data_log = "None"
        reason = "Nessun tentativo riuscito"
        prompt_tokens = 0
        completion_tokens = 0
        latency_ms = 0.0

        max_attempts = cfg_llm.get("max_attempts", 2)
        temp_initial = cfg_llm.get("temperature", 0.1)
        temp_retry = cfg_llm.get("temperature_retry", 0.2)
        max_tokens = cfg_llm.get("max_tokens", 300)
        reasoning_effort = cfg_llm.get("reasoning_effort", "low")

        for attempt in range(max_attempts):
            try:
                t0 = time.perf_counter()
                
                completion = await self.client.chat.completions.create( # Chiamata API di Groq
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user",   "content": user_prompt},
                    ],
                    model=GROQ_MODEL,
                    temperature=temp_initial if attempt == 0 else temp_retry,
                    max_tokens=max_tokens,
                    reasoning_effort=reasoning_effort,
                    response_format={
                        "type": "json_schema",
                        "json_schema": MODBUS_RESPONSE_SCHEMA,
                    },
                )
                
                t1 = time.perf_counter()
                latency_ms = (t1 - t0) * 1000

                if completion.usage: 
                    prompt_tokens = completion.usage.prompt_tokens
                    completion_tokens = completion.usage.completion_tokens

                raw_text = completion.choices[0].message.content.strip() 
                _logger.debug(f"Risposta LLM raw: {raw_text[:300]}")

                llm_json = json.loads(raw_text)
                response_bytes = _build_response_bytes(function_code, llm_json) # Costruisce la risposta bytes

                reason = llm_json.get("reason", "")
                _logger.info(
                    f"LLM decision FC={function_code}: action={llm_json.get('action')}"
                    + (f", reason: {reason}" if reason else "")
                )
                
                action_log = llm_json.get("action")
                exc_code_log = llm_json.get("exception_code")
                resp_data_log = str(llm_json.get("response_data"))
                
                break # Successo: esce dal loop di retry

            except RateLimitError as e: # Gestisce superamento temporaneo quote Groq
                _logger.warning(f"Rate limit Groq raggiunto (tentativo {attempt+1}/{max_attempts}). Attesa di 15s prima del retry: {e}")
                await asyncio.sleep(15)

            except (json.JSONDecodeError, ValueError) as e: # Gestisce errori logici nel parsing
                _logger.warning(f"LLM ha restituito JSON non valido (tentativo {attempt+1}/{max_attempts}): {e}")
                await asyncio.sleep(2)

            except Exception as e: # Gestisce altri errori API/rete
                _logger.error(f"Errore chiamata LLM (tentativo {attempt+1}/{max_attempts}): {e}")
                await asyncio.sleep(6)  # Backoff di sicurezza prima del retry

        else:
            # Tutti i tentativi falliti: i valori di fallback (già inizializzati sopra) rimangono invariati
            action_log = "errore_fallback"
            reason = f"Tutti i {max_attempts} tentativi LLM falliti. Fallback: ILLEGAL_FUNCTION (0x01)."

        # Deduce il tipo di test per l'analisi in base al payload
        test_type = "fc_sweep" if raw_data == b"\xaa\xbb\xcc" else "payload_probe"

        # Salva l'output in un file JSONL
        stat_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "stat")
        os.makedirs(stat_dir, exist_ok=True)
        json_path = os.path.join(stat_dir, "llm_residual_responses.jsonl")
        
        log_entry = {
            "test_type": test_type,
            "function_code": function_code,
            "payload_hex": payload_hex,
            "action": action_log,
            "exception_code": exc_code_log,
            "response_data": resp_data_log,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_ms": round(latency_ms, 1),
            "reason": reason
        }
        
        with open(json_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

        return response_bytes


llm_client = LLMClient()
