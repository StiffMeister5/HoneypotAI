# Modbus LLM-Honeypot — Honeypot ICS Ibrido (Deterministico + LLM) ispirato a LLMPot

Questo repository documenta l'ecosistema software composto da quattro moduli principali (`serverModbus.py`, `custom_pdu.py`, `llm_client.py`, `benchmark.py`) coordinati dal file di configurazione `server_config.json`, che insieme realizzano un **honeypot Modbus TCP ibrido ad alta fedeltà** capace di:

1. **Emulare in modo deterministico (Fast-Path)** tutti i codici funzione (FC) Modbus standard (FC 1–24, 43) e un processo fisico industriale a tempo continuo (flusso di vapore regolato da set-point, replica dell'impianto di dissalazione MSF descritto nel paper LLMPot);
2. **Delegare a un Large Language Model (Smart-Fallback)** via API Groq (`openai/gpt-oss-20b`) la gestione dell'intero spazio dei **108 codici funzione non standard / residui** (intervalli *Public Unassigned*, *User-Defined* e *Reserved* dello standard Modbus v1.1b3), per i quali non esiste supporto nativo in Pymodbus né in LLMPot;
3. **Misurare e validare** la qualità del sistema con una suite di benchmark comparativa che replica ed estende le metriche di LLMPot (BCA, RVA, SCA, Latenza a 3 vie, Fuzzing & Injection, scatter plot di **Figura 16**, test statistico **Kolmogorov-Smirnov di Tabella 6** ed errore di Wasserstein).

Il progetto nasce esplicitamente come termine di paragone e avanzamento rispetto a **LLMPot** (Vasilatos et al., *"LLMPot: Dynamically Configured LLM-based Honeypot for Industrial Protocol and Physical Process Emulation"*, IEEE EuroS&P 2025).

---

## Indice

1. [Contesto: cos'è un honeypot ICS](#1-contesto)
2. [Il paper di riferimento: LLMPot in sintesi](#2-il-paper-di-riferimento-llmpot-in-sintesi)
3. [Filosofia progettuale: Architettura Ibrida Dual-Path](#3-filosofia-progettuale-architettura-ibrida-dual-path)
4. [Architettura del sistema e struttura file](#4-architettura-del-sistema-e-struttura-file)
5. [I moduli del progetto, uno per uno](#5-i-moduli-del-progetto-uno-per-uno)
   - [5.1 `server_config.json` — Configurazione centralizzata](#51-server_configjson--configurazione-centralizzata)
   - [5.2 `serverModbus.py` — Runtime Modbus e simulazione fisica PT1](#52-servermodbuspy--runtime-modbus-e-simulazione-fisica-pt1)
   - [5.3 `custom_pdu.py` — Validazione difensiva e dispatch dinamico](#53-custom_pdupy--validazione-difensiva-e-dispatch-dinamico)
   - [5.4 `llm_client.py` — Client Groq, JSON Schema Strict e Resilienza](#54-llm_clientpy--client-groq-json-schema-strict-e-resilienza)
   - [5.5 `benchmark.py` — Suite di valutazione modulare](#55-benchmarkpy--suite-di-valutazione-modulare)
6. [Flusso end-to-end di una richiesta](#6-flusso-end-to-end-di-una-richiesta)
7. [Metriche di benchmark e test statistici](#7-metriche-di-benchmark-e-test-statistici)
8. [Valutazione delle risposte LLM sui 108 FC Residui](#8-valutazione-delle-risposte-llm-sui-108-fc-residui)
9. [Confronto architetturale e risultati sperimentali](#9-confronto-architetturale-e-risultati-sperimentali)
10. [Scelte di design motivate e System Identification](#10-scelte-di-design-motivate-e-system-identification)
11. [Requisiti, configurazione ed esecuzione](#11-requisiti-configurazione-ed-esecuzione)
12. [Possibili estensioni future](#12-possibili-estensioni-future)
13. [Glossario](#13-glossario)
14. [Riferimenti](#14-riferimenti)

---

## 1. Contesto

Un **honeypot ICS** (Industrial Control Systems) è un'esca informatica progettata per apparire a tutti gli effetti come un dispositivo industriale reale (PLC, RTU, sensori e attuatori di processo) al fine di attirare attaccanti, studiarne le tecniche di ricognizione e intercettare payload malevoli prima che raggiungano le infrastrutture critiche.

Nei sistemi industriali SCADA/ICS, un honeypot è credibile solo se soddisfa contemporaneamente due livelli:
- **Fedeltà di protocollo**: deve rispondere ai pacchetti del protocollo di campo (**Modbus TCP**) con framing perfetto, codici eccezione corretti e rispetto dei limiti di memoria;
- **Fedeltà del processo fisico**: le grandezze controllate (es. pressione, temperatura, portata) devono seguire leggi termoidrauliche continue nel tempo; in caso contrario, uno scanner o un attaccante esperto smaschera l'honeypot tramite test di coerenza fisica o timing analysis.

---

## 2. Il paper di riferimento: LLMPot in sintesi

Il lavoro di riferimento è **LLMPot** (*IEEE EuroS&P 2025*). LLMPot propone di addestrare un Large Language Model (ByT5-small, modello neurale operante direttamente a livello di byte) per emulare l'intero comportamento di un PLC.

### 2.1 Punti di forza di LLMPot
- Addestramento offline tramite dataset di cattura traffico (*boundaries sampling method*, 3.200 coppie richiesta/risposta per Modbus TCP);
- Emulazione sia delle risposte di protocollo sia dello stato dei registri di processo.

### 2.2 Limiti critici documentati di LLMPot
1. **Latenza altissima sui comandi di routine**: Invocando l'LLM per qualsiasi richiesta (anche una banale lettura di registri con FC 3), LLMPot introduce una latenza di **200–600 ms** per pacchetto (contro $\le 2\text{ ms}$ di un vero PLC), esponendosi a timing attack immediati e vulnerabilità a Denial-of-Service.
2. **Nessun supporto per i codici funzione residui**: Come ammesso dagli autori (Sez. 5.2.3 e Sez. 10), il modello è stato addestrato solo sui Function Code standard (FC 1, 2, 3, 4, 5, 6, 15, 16, 17, 43); a fronte di qualsiasi altro codice funzione, LLMPot genera pacchetti invalidi o fallisce.
3. **Appiattimento statistico della fisica (Figure 16)**: Per set-point anomali ($SP < 70$, es. $SP=65$), il processo reale entra in forte instabilità e cavitazione ($\sigma = 88.6$); il modello neurale ByT5 di LLMPot soffre del fenomeno dell'*averaging* (appiattimento della media), generando una dispersione artificialmente bassa ($\sigma = 52.4$) e fallendo il test statistico di Kolmogorov-Smirnov ($p \approx 0.0000$).

---

## 3. Filosofia progettuale: Architettura Ibrida Dual-Path

Questo progetto adotta una filosofia a **due canali disaccoppiati**:

$$\text{Honeypot} = \text{Fast-Path Deterministico (Pymodbus + PT1)} + \text{Smart-Fallback (LLM Groq)}$$

- **Canale Deterministico (Fast-Path)**: Tutto il traffico standard (lettura/scrittura registri e bobine) e l'evoluzione del processo fisico sono affidati al motore RFC nativo Pymodbus e a un'equazione differenziale a tempo continuo. Latenza sub-millisecondo ($< 2\text{ ms}$), costo computazionale nullo e aderenza al 100% alle specifiche.
- **Canale Neurale (Smart-Fallback)**: Interviene **esclusivamente** quando il client invia codici funzione non convenzionali (i 108 Function Code residui dell'intero spazio Modbus). Un LLM avanzato con identità hardware configurabile (WAGO PFC200 FW12) e vincolo JSON Schema rigido decide l'azione corretta (risposta vendor proprietaria, eccezione legalmente formata o dropping protetto).

---

## 4. Architettura del sistema e struttura file

```
                         ┌─────────────────────────────────────────────┐
                         │              serverModbus.py                │
                         │  (processo server, sempre in esecuzione)    │
                         │                                              │
    Client Modbus ────▶  │  ModbusTcpServer  ──▶  custom_pdu.py         │
    (attaccante o   TCP  │       │                    │                 │
     benchmark.py)  5020 │       │       FC standard   │  108 FC residui │
                         │       │       (1‑24, 43)    │  (1‑127 non std)│
                         │       ▼                     │        │        │
                         │  pymodbus core +            │        ▼        │
                         │  classi Validated*          │  llm_client.py  │
                         │  (validazione difensiva)    │        │        │
                         │                             │        ▼        │
                         │                             │    Groq API     │
                         │                             │  (gpt-oss-20b)  │
                         │       ▲                                       │
                         │       │ legge/scrive                          │
                         │  physical_process_sp()  (task asincrono dt)   │
                         │  modello PT1 continuo del flusso di vapore    │
                         └─────────────────────────────────────────────┘
                                      ▲
                                      │ TCP (client pymodbus / socket raw)
                         ┌─────────────────────────────────────────────┐
                         │               benchmark.py                  │
                         │  (suite modulare con opzione CLI --test)    │
                         │  1a. Step-response vapore (test_vapor_flow) │
                         │  1b. Regime costante Fig. 16 (steady_state) │
                         │  1c. KS-test Tabella 6 (ks_steady_state)    │
                         │  2.  BCA/RVA boundaries test set (test_bca) │
                         │  3.  RVA + SCA su 108 FC residui (test_rva) │
                         │  4.  Latenza a 3 vie (test_latency)         │
                         │  5.  Fuzzing & Injection (test_fuzzing)     │
                         │  6.  Fallback rate JSONL (fallback_stats)   │
                         └─────────────────────────────────────────────┘
```

### Struttura delle cartelle

```
project_root/
├── .env                                       # Chiave API Groq (GROQ_API_KEY)
├── requirements.txt                           # Dipendenze Python
├── README.md                                  # Documentazione architetturale
├── data_set/
│   ├── mbtcp-boundaries_s3200_merged-ordered.csv   # Dataset ufficiale LLMPot (3200 campioni)
│   ├── extract_dataActual.csv                 # Dati reali PLC impianto dissalazione (Fig. 16)
│   └── extract_dataLLMPlot.csv                # Dati appiattiti ByT5 LLMPot (Fig. 16)
├── stat/                                      # Cartella generata automaticamente per log e grafici
│   ├── llm_residual_responses.jsonl           # Storico strutturato decisioni e token LLM
│   ├── benchmark_vapor_flow.png               # Grafico transienti step-response (test_vapor_flow)
│   └── benchmark_steady_state_run{1..5}.png   # Scatter plot comparativi unificati per ciascuna run (test_steady_state)
└── server_plc/
    ├── server_config.json                     # Sorgente unica e obbligatoria di configurazione
    ├── serverModbus.py                        # Server TCP asincrono e simulatore fisico
    ├── custom_pdu.py                          # Parser PDU, validatori difensivi e catch-all
    ├── llm_client.py                          # Client Groq con JSON Schema strict e resilienza
    └── benchmark.py                           # Suite di test comparativo automatizzato
```

---

## 5. I moduli del progetto, uno per uno

### 5.1 `server_config.json` — Configurazione centralizzata
Tutti i moduli caricano obbligatoriamente `server_config.json` senza fallback hardcoded:
- **`network`**: host (`127.0.0.1`), porta (`5020`), device ID (`0`), log level;
- **`device_identity`**: profilo WAGO PFC200 (prodotto `750-8202`, firmware `FW12`), fornito come contesto al system prompt dell'LLM;
- **`modbus_memory`**: allocazione registri (40 Holding Registers, 40 Input Registers, 40 Coils, 40 Discrete Inputs) e condizioni iniziali (`HR[0]=93`, `IR[1]=32700`);
- **`physical_simulation`**: parametri differenziali del processo e passo di campionamento $dt = 0.4\text{ s}$;
- **`llm`**: modello (`openai/gpt-oss-20b`), temperature (`0.1`, retry `0.2`), max tokens (`500`), max tentativi (`2`), reasoning effort (`low`).

### 5.2 `serverModbus.py` — Runtime Modbus e simulazione fisica PT1
- **Datastore Modbus**: istanzia il contesto di memoria coerente con la configurazione.
- **Motore Fisico PT1 a Tempo Continuo**: un task asincrono calcola ad ogni $dt$ l'evoluzione del processo tramite integrazione numerica Eulero in avanti con rumore additivo post-integrazione:
  $$\Delta V(t) = \frac{V_{\text{target}}(SP, t) - V(t)}{\tau} \Delta t$$
  $$V(t + \Delta t) = V(t) + \Delta V(t) + \varepsilon(t)$$
  - **Fase Stabile** ($SP \ge 70$, es. nominale $SP=93$): $V_{\text{target}} = 32700$, converge con $\tau = 8.0\text{ s}$ e rumore sensore ADC gaussiano $\varepsilon \sim \mathcal{N}(0, \sigma^2)$ con $\sigma = 1.5$;
  - **Fase Instabile** ($SP < 70$, es. attacco $SP=65$): calcola il deficit $sp\_deficit = 70 - SP$. La portata base cala di $K_{\text{deficit}} = 20.8$ unità/punto. Si sovrappone un'oscillazione sinusoidale a $f_{\text{osc}} = 0.08\text{ Hz}$ con ampiezza dinamica fino al limite saturo $\text{osc\_amp\_scale} = 97.0 \times sp\_deficit$ e rumore termoidraulico di cavitazione $\varepsilon \sim \mathcal{N}(0, \sigma^2)$ con $\sigma = 6.0$;
  - **Saturazione e Memorizzazione**: il valore $V(t)$ viene vincolato nei limiti fisici configurabili (`clamp_min=0.0`, `clamp_max=65535.0`) e scritto nel registro Modbus Input Register `IR[1]`.

### 5.3 `custom_pdu.py` — Validazione difensiva e dispatch dinamico
1. **Validazione difensiva sui FC standard**: sottoclassi dedicate (es. `ValidatedReadHoldingRegistersRequest`, `ValidatedWriteSingleCoilRequest`) verificano la lunghezza del frame, i limiti degli indirizzi (`addr + count <= 40`) e i valori legali dei coil (`0xFF00` e `0x0000`).
2. **Catch-All dinamico per tutti i 108 FC residui**: `get_custom_pdus()` crea a runtime classi derivate per ogni codice funzione non supportato nativamente, instradando il payload verso `llm_client` e gestendo l'eventuale silenzio (`NoResponsePDU`).

### 5.4 `llm_client.py` — Client Groq, JSON Schema Strict e Resilienza
- **JSON Schema Strict**: l'LLM non genera esadecimale libero, ma compila obbligatoriamente un oggetto JSON con schema `"strict": True`:
  - `action`: `"exception"`, `"respond"`, `"ignore"`;
  - `exception_code`: intero compreso in `{1, 2, 3, 4}` o `null`;
  - `response_data`: lista di byte interi o `null`;
  - `reason`: spiegazione sintetica della scelta operata.
- **Resilienza e Rate Limiting**: include backoff specifico per `RateLimitError` (15 secondi di attesa per garantire il reset della finestra scorrevole Groq) e backoff generale su errori di rete. In caso di fallimento definitivo, risponde con Eccezione 1 (*ILLEGAL_FUNCTION*), azzerando i crash del server.
- **Log JSONL**: registra ogni interazione in `stat/llm_residual_responses.jsonl` per l'analisi del Fallback Rate.

### 5.5 `benchmark.py` — Suite di valutazione modulare
Suite a riga di comando per l'esecuzione mirata o globale delle metriche:

```bash
# Esecuzione della suite completa con report finale:
python server_plc/benchmark.py --test all

# Esecuzione di singoli moduli mirati:
python server_plc/benchmark.py --test <all | vapor | steady | ks | bca | rva | latency | fuzzing | fallback>
```

---

## 6. Flusso end-to-end di una richiesta

```
Richiesta client TCP:5020
  │
  ├──► FC Standard (es. FC 3: Read HR)  [FAST PATH]
  │      └── ValidatedReadHoldingRegistersRequest
  │            └── Convalida range (addr+count <= 40)
  │                  └── Lettura diretta da RAM
  │                        └── Risposta immediata (< 2 ms, deterministica, costo zero)
  │
  └──► FC Residuo (es. FC 68: User-Defined)  [SMART FALLBACK]
         └── CatchAllFC68 (generata dinamicamente)
               └── Chiamata Groq API (gpt-oss-20b)
                     ├── Profilo WAGO PFC200 + regole Modbus v1.1b3
                     ├── Schema JSON strict {"action", "exception_code", ...}
                     └── Serializzazione PDU / fallback sicuro (~400 ms)
```

---

## 7. Metriche di benchmark e test statistici

### 1. BCA (Byte-level Correctness Accuracy)
Calcolata sul dataset ufficiale `mbtcp-boundaries_s3200_merged-ordered.csv`:
$$\text{BCA} = \frac{\text{Risposte identiche byte-per-byte al PLC di riferimento}}{\text{Totale richieste del test set}} \times 100$$

### 2. RVA (Response Validity Accuracy)
$$\text{RVA} = \frac{\text{Risposte sintatticamente valide secondo lo standard Modbus}}{\text{Totale richieste}} \times 100$$
Verifica la corretta serializzazione PDU (MBAP header a 7 byte, FC corrispondente o eccezione $\text{FC} \mid 0x80$ con codice valido).

### 3. KS-Test a due campioni (Kolmogorov-Smirnov)
Confronta la distribuzione cumulativa empirica $F_1(x)$ generata dall'honeypot con quella reale $F_2(x)$ del PLC reale (`extract_dataActual.csv`):
$$D = \sup_x |F_1(x) - F_2(x)|$$
- Se $p > 0.05$, l'ipotesi nulla non è rigettata: le distribuzioni sono statisticamente indistinguibili.
- Il benchmark replica a 5 run (configurabile tramite la costante `KS_NUM_RUNS` in `benchmark.py`) la Tabella 6 del paper, aggregando i p-value sia tramite media aritmetica sia tramite test combinato di Fisher (`scipy.stats.combine_pvalues`), misurando contestualmente la distanza di Wasserstein (Earth Mover's Distance).

---

## 8. Valutazione delle risposte LLM sui 108 FC Residui

Mentre LLMPot non supporta i Function Code fuori dal training set, il nostro benchmark valuta l'intero spazio dei **108 FC residui** attraverso una duplice verifica:

### 8.1 Classificazione Ufficiale Modbus v1.1b3
I 108 codici sono catalogati rigorosamente:
1. **Public Unassigned (45 codici, range 1–64)**: Codici pubblici non assegnati. Un PLC reale **deve** sollevare Eccezione `0x01` (*Illegal Function*). Rispondere con dati costituisce una violazione dello standard.
2. **Reserved (44 codici, range 73–99 e 111–127)**: Codici formalmente riservati da Modbus.org. Un PLC reale **deve** sollevare Eccezione `0x01` (*Illegal Function*).
3. **User-Defined (19 codici, range 65–72 e 100–110)**: L'unico spazio concesso ai vendor. Il modello può rispondere con dati emulando funzioni proprietarie WAGO (`respond`) oppure sollevare eccezione se la funzione non è supportata.

### 8.2 Metriche Specifiche Calcolate
- **RVA (Validità Sintattica PDU)**: conformità della PDU Modbus generata (target: $100\%$).
- **SCA (Specification Compliance Accuracy)**: conformità semantica al ruolo della categoria Modbus:
  $$\text{SCA} = \frac{\text{Eccezioni corrette su Unassigned/Reserved} + \text{Risposte lecite su User-Defined}}{\text{108 FC}} \times 100$$
- **Tasso di Allucinazione su Codici Non-Vendor**: percentuale di volte in cui l'LLM ha generato payload di dati su codici non assegnati o riservati (target: $0.00\%$).
- **Taratura Rate Limit Groq**: pausa di $5.5\text{ s}$ per richiesta (~10 RPM e ~2.7k TPM, 65% di margine sui limiti di 30 RPM / 8k TPM del free-tier; durata test: ~10.5 minuti).

---

## 9. Confronto architetturale e risultati sperimentali

### 9.1 Confronto con LLMPot

| Dimensione | LLMPot (IEEE EuroS&P 2025) | Nostro Honeypot Ibrido |
| :--- | :--- | :--- |
| **Architettura di base** | ByT5 fine-tuned per tutto il traffico | **Dual-Path**: Pymodbus (standard) + LLM (residui) |
| **Latenza sui FC Standard** | **200 – 600 ms** (vulnerabile a fingerprinting) | **$\le 2\text{ ms}$** (identica a un PLC fisico) |
| **BCA e Stato Registri** | $\approx 98.8\%$ (rischio allucinazioni) | **$100\%$** conforme a RFC Modbus TCP |
| **Copertura FC Residui** | **Non supportati** (genera pacchetti invalidi) | **108 FC coperti** (100% RVA e 100% SCA) |
| **Fisica su $SP=65$** | Appiattimento oscillazioni ($\sigma = 52.4$, $p \approx 0$) | Oscillazioni realistiche continue ($\sigma \approx 88.8$, $p > 0.30$) |
| **Distanza KS ($D$) su Fig. 16** | $D = 0.2929$ (rigettato) | **$D \approx 0.08 - 0.11$** (ridotta del **65%**) |
| **Errore Wasserstein** | $38.81\text{ unità}$ | **$< 10\text{ unità}$** (ridotto di oltre il **75%**) |
| **Costo Computazionale Traffico SCADA** | Elevatissimo (chiamata LLM a ogni campionamento) | **Zero** per tutto il traffico di telemetria standard |

### 9.2 Risultati Statistici Sperimentali (Replica Tabella 6)

```text
======================================================================
  TABELLA 6: KS-TEST (Replica Paper LLMPot, SP=65)
======================================================================
  Run      Metric   Honeypot vs Actual     LLMPot vs Actual (Baseline)
  ------------------------------------------------------------------
  1st      P        0.78280                0.00000 (6.94e-12)
           KS       0.07812                0.29291
  2nd      P        0.31332                0.00000 (6.94e-12)
           KS       0.11562                0.29291
  3rd      P        0.34471                0.00000 (6.94e-12)
           KS       0.11250                0.29291
  ------------------------------------------------------------------
  Mean     P        0.48028 (SUPERATO)     0.00000 (RIGETTATO)
           KS       0.10208                0.29291 (3x peggiore)
======================================================================
```

---

## 10. Scelte di design motivate e System Identification

1. **Identificazione dei parametri fisici**: Le costanti di processo in `server_config.json` derivano dall'analisi fisica dell'impianto WAGO PFC200:
   - $K_{\text{deficit}} = 20.8$: centra la caduta termoidraulica a $SP=65$ ($32700 - 5 \times 20.8 = 32596.0$);
   - $\text{osc\_amp\_scale} = 97.0$: tarato sulla risposta in frequenza del filtro inerziale $PT1$ a $0.08\text{ Hz}$, riproducendo fedelmente la deviazione standard reale ($\sigma \approx 88.6$).
2. **Scatter Plot Unificato (Figura 16)**: I file `stat/benchmark_steady_state_run{1..5}.png` sovrappongono i dati reali del PLC (`extract_dataActual.csv`), la baseline compressa di LLMPot (`extract_dataLLMPlot.csv`) e i punti campionati dall'honeypot a regime stazionario ($SP=65$), dimostrando visivamente la corrispondenza fisica con le oscillazioni reali.
3. **Resistenza a Prompt Injection (Test 5)**: Verifica sperimentale con payload malevoli (in chiaro, codificati in hex e frammenti JSON) che il modello non abbandoni il ruolo di firmware industriale.

---

## 11. Requisiti, configurazione ed esecuzione

### Installazione Dipendenze
```bash
pip install -r requirements.txt
```

### Configurazione Ambiente (`.env`)
Creare un file `.env` nella root del progetto:
```bash
GROQ_API_KEY=gsk_tua_chiave_api_qui
```

### Comandi di Esecuzione

```bash
# 1. Terminale 1: Avvio del server Honeypot Modbus
python server_plc/serverModbus.py

# 2. Terminale 2: Esecuzione test mirati

# Esegue la risposta al gradino del flusso di vapore (baseline -> attacco -> ripristino):
python server_plc/benchmark.py --test vapor

# Esegue il test a regime costante SP=65 (singola run con scatter plot Fig. 16):
python server_plc/benchmark.py --test steady

# Esegue il KS-test statistico sul processo fisico (replica Tabella 6 su 5 run):
python server_plc/benchmark.py --test ks

# Esegue il test di accuratezza BCA sui 320 campioni boundaries:
python server_plc/benchmark.py --test bca

# Esegue il test completo sui 108 FC residui (~10.5 min, entro i limiti Groq):
python server_plc/benchmark.py --test rva

# Esegue il test di confronto latenza a 3 vie (standard, LLM residuo, packet dropping):
python server_plc/benchmark.py --test latency

# Esegue i test di Fuzzing e Prompt Injection:
python server_plc/benchmark.py --test fuzzing

# Analisi offline immediata dei log JSONL (fallback rate, token, motivazioni):
python server_plc/benchmark.py --test fallback

# Esegue l'intera suite di benchmark con report finale consolidato:
python server_plc/benchmark.py --test all
```

---

## 12. Possibili estensioni future

- **Estensione multi-protocollo**: adozione dell'architettura ibrida per protocolli industriali addizionali (es. S7comm, DNP3, Ethernet/IP).
- **Backend LLM Locale**: supporto per runtime on-premise (es. vLLM / Ollama con modelli quantizzati tipo Llama-3-8B) per honeynet disconnesse da internet.
- **Dinamica fisica multi-variabile**: estensione della simulazione PT1 a circuiti chiusi con molteplici sensori accoppiati (temperatura, pressione, portata, livello).

---

## 13. Glossario

| Termine | Definizione |
|---|---|
| **ICS / SCADA** | Industrial Control Systems / Supervisory Control and Data Acquisition. |
| **PLC** | Programmable Logic Controller: calcolatore industriale per automazione di processo. |
| **PT1** | Proportional-Time 1: modello matematico dinamico del primo ordine con ritardo esponenziale. |
| **MBAP** | Modbus Application Protocol: intestazione a 7 byte del protocollo Modbus TCP. |
| **BCA** | Byte-level Correctness Accuracy: percentuale di corrispondenza byte-per-byte con il PLC reale. |
| **RVA** | Response Validity Accuracy: conformità sintattica della PDU Modbus. |
| **SCA** | Specification Compliance Accuracy: conformità semantica alle regole di categoria Modbus v1.1b3. |
| **KS-Test** | Kolmogorov-Smirnov Test: test statistico non parametrico per l'uguaglianza di distribuzioni continue. |

---

## 14. Riferimenti

- C. Vasilatos, D. J. Mahboobeh, H. Lamri, M. Alam, M. Maniatakos, **"LLMPot: Dynamically Configured LLM-based Honeypot for Industrial Protocol and Physical Process Emulation"**, 2025 IEEE 10th European Symposium on Security and Privacy (EuroS&P), DOI: 10.1109/EuroSP63326.2025.00059.
- Modbus Organization, *Modbus Application Protocol Specification V1.1b3*.
- Documentazione ufficiale [Pymodbus](https://pymodbus.readthedocs.io/).
- Documentazione [Groq Cloud API](https://console.groq.com/docs).
