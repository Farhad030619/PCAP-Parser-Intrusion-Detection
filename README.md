# PCAP-Parser & Intrusion Detection System (IDS)

Detta är ett Python-baserat Intrusion Detection System (IDS) och PCAP-analysverktyg för nätverkssäkerhet. Verktyget analyserar nätverkstrafik från en `.pcap`-fil för att upptäcka misstänkt aktivitet och genererar varningar (alerts) vid misstänkta mönster.

---

## Översikt och Detektion

Verktyget analyserar paket i realtid med hjälp av Scapy och kan upptäcka följande nätverkshot:

1. **Portskanningar (Port Scans)**:
   - Detekterar om en enskild käll-IP skannar flera unika destinationsportar (TCP eller UDP) inom ett definierat tidsfönster (sliding window).
   - Inkluderar intelligent undertryckning (suppression/cooldown) av dubbla larm under tidsfönstret för att undvika loggspam.
   
2. **SYN-Flood DoS (Denial of Service)**:
   - Detekterar om en enskild käll-IP skickar en stor mängd TCP SYN-paket men får orimligt få SYN-ACK-svar tillbaka (eller inga alls).
   - Utvärderar både under analysens gång och i slutet för att identifiera attacker med hög precision baserat på tröskelvärden och kvoter (ratio).

---

## Kodstruktur

Projektets filer är strukturerade på följande sätt:

- **`src/`**
  - **`analyzer.py`**: Innehåller klassen `NetworkAnalyzer` som sköter kärnlogiken för analys, tillståndsmaskiner för anslutningar, glidande tidsfönster och varningsgenerering.
  - **`cli.py`**: Kommandoradsgränssnitt (CLI) som hanterar argument, sätter upp loggning och strömmar PCAP-filer till analysatorn.
- **`tests/`**
  - **`test_analyzer.py`**: Omfattande testsvit som verifierar detektionsregler, gränsvärden, rensning av historik och CLI-funktionalitet.
- **`pyproject.toml` & `requirements.txt`**: Beroendehantering och projektkonfiguration.
- **`WIRESHARK_GUIDE.md`**: Guide för att generera test-PCAP-filer med Wireshark, `nmap` och `hping3`.

---

## Installation

För att köra verktyget lokalt behöver du Python 3.12+ installerat.

1. **Klona eller ladda ner projektet** till din lokala maskin.
2. **Skapa en virtuell miljö**:
   ```bash
   python3 -m venv .venv
   ```
3. **Aktivera den virtuella miljön**:
   - På macOS/Linux:
     ```bash
     source .venv/bin/activate
     ```
   - På Windows (Command Prompt):
     ```cmd
     .venv\Scripts\activate.bat
     ```
   - På Windows (PowerShell):
     ```powershell
     .venv\Scripts\Activate.ps1
     ```
4. **Installera beroenden**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Användning

CLI-verktyget tar en `.pcap`-fil som inmatning och erbjuder flexibla flaggor för att anpassa detektionskriterierna.

### Grundläggande kommando
Kör skriptet med standardinställningar (skanningsgräns på 20 portar per 5.0 sekunder, syn-flood gräns på 100 SYN-paket med en kvot på 10.0):

```bash
python3 src/cli.py path/to/capture.pcap
```

### Anpassade tröskelvärden
Du kan anpassa tröskelvärden, tidsfönster och utmatningsfil för larmen med hjälp av flaggor:

```bash
python3 src/cli.py path/to/capture.pcap -t 20 -w 5.0 --syn-threshold 100 --syn-ratio 10.0 -o alerts.log
```

#### Tillgängliga flaggor och parametrar:
- `pcap_file` (Positionsparameter): Sökvägen till den PCAP-fil som ska analyseras.
- `-t`, `--port-threshold`: Antal unika destinationsportar som måste skannas inom fönstret för att utlösa en portskanning-varning (standard: `20`).
- `-w`, `--port-window`: Det glidande tidsfönstret (i sekunder) för portskanning och tystnad (cooldown) (standard: `5.0`).
- `--syn-threshold`: Minsta antal SYN-paket skickade av en IP för att betraktas som en SYN-flood (standard: `100`).
- `--syn-ratio`: Minsta tillåtna förhållande (kvot) mellan skickade SYN-paket och mottagna SYN-ACK-paket för att utlösa larm (standard: `10.0`).
- `-o`, `--output-log`: Sökvägen till loggfilen där varningar sparas (standard: `ids_alerts.log`).

---

## Köra Tester

Projektet har en komplett testsvit skriven i `pytest` för att säkerställa att analysatorn och CLI fungerar korrekt.

Med aktiverad virtuell miljö, kör:

```bash
pytest
```

Eller direkt via sökvägen till venv-pytest:

```bash
.venv/bin/pytest
```
