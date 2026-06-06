# PCAP-Parser & Intrusion Detection System (IDS)

Detta är ett Python-baserat Intrusion Detection System (IDS) och PCAP-analysverktyg för nätverkssäkerhet. Verktyget analyserar nätverkstrafik i realtid eller från en `.pcap`-fil för att upptäcka misstänkt aktivitet och genererar varningar (alerts) i en lokal loggfil samt på ett webb-dashboard.

---

## Översikt och Detektion

Verktyget analyserar paket i realtid med hjälp av Scapy och har 4 specialiserade detektionsmotorer:

1. **SYN-Flood DoS (Denial of Service)**:
   - Detekterar om en enskild käll-IP skickar en stor mängd TCP SYN-paket men får orimligt få SYN-ACK-svar tillbaka (eller inga alls), vilket tyder på ett överbelastningsförsök.

2. **ARP-Spoofing (Man-in-the-Middle)**:
   - Detekterar ARP-cacheförgiftning genom att övervaka och matcha IP- till MAC-adresser. Om en enskild IP-adress på nätverket plötsligt associeras med flera olika MAC-adresser i ARP-svar, flaggas detta omedelbart som en MitM-attack.

3. **DNS-Tunneling (Dataexfiltrering)**:
   - Identifierar dolda DNS-tunnlar genom att hålla reda på längden och frekvensen på DNS-frågor från käll-IP-adresser. Om en IP skickar många ovanligt långa DNS-förfrågningar (t.ex. subdomäner som innehåller krypterad data), utlöses ett larm.

4. **Brute-Force & Portskanning (TCP Connections)**:
   - Upptäcker snabba, upprepade anslutningsförsök (TCP SYN) från en enskild käll-IP inom ett glidande tidsfönster (t.ex. 20 anslutningar på 10 sekunder). Detta flaggar potentiella brute-force-försök eller portskanningar.

---

## Kodstruktur

Projektets filer är strukturerade på följande sätt:

- **`src/`**
  - **`analyzer.py`**: Innehåller klassen `NetworkAnalyzer` som sköter kärnlogiken för de 4 detektionsmotorerna.
  - **`web_ui.py`**: FastAPI-baserad webbserver och WebSocket-anslutning för visualisering i realtid. Spara även varningar i loggfilen.
  - **`cli.py`**: Kommandoradsgränssnitt (CLI) som hanterar argument, sätter upp loggning och analyserar PCAP-filer eller kör live-sniffning.
- **`tests/`**
  - **`test_analyzer.py`**: Omfattande testsvit som verifierar de 4 detektionsreglerna, gränsvärden och CLI-funktionalitet.
  - **`test_web.py`**: Verifierar webbserverns API:er, WebSocket-strömmar och trådsäkerhet.
- **`services.json`**: Konfiguration av kända tjänster (t.ex. YouTube, Spotify, LinkedIn, Telegram) med matchande DNS-nyckelord.
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
   - På Windows:
     ```cmd
     .venv\Scripts\activate.bat
     ```
4. **Installera beroenden**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Användning (CLI)

CLI-verktyget tar antingen en `.pcap`-fil eller ett live-gränssnitt som inmatning och erbjuder flexibla flaggor.

### Grundläggande kommando (PCAP-fil)
Kör skriptet med standardinställningar (skannar efter SYN-flood med tröskel på 100 SYN-paket och kvot på 10.0):

```bash
python3 src/cli.py path/to/capture.pcap
```

### Live-sniffning i realtid (Live Sniffing)
Verktyget kan även sniffa nätverkstrafik direkt i realtid från ett nätverksgränssnitt. 

> [!IMPORTANT]
> Live-sniffning kräver root-privilegier (administratörsrättigheter via `sudo`) på macOS och Linux för att kunna läsa rå nätverkstrafik direkt från nätverksgränssnittet.

**Exempel på live-sniffning på standardgränssnittet:**
```bash
sudo python3 src/cli.py --live
```

**Exempel på live-sniffning på ett specifikt gränssnitt (t.ex. `en0`):**
```bash
sudo python3 src/cli.py --live -i en0
```

### Anpassade inställningar
Du kan anpassa tröskelvärden för SYN-flood samt utmatningsfil för larmen med hjälp av flaggor:

```bash
python3 src/cli.py path/to/capture.pcap --syn-threshold 50 --syn-ratio 5.0 -o alerts.log
```

#### Tillgängliga flaggor och parametrar:
- `pcap_file` (Positionsparameter): Sökvägen till den PCAP-fil som ska analyseras (krävs ej om `--live` används).
- `--live`: Sniffa nätverkstrafik live i realtid.
- `-i`, `--interface`: Nätverksgränssnitt att sniffa på (t.ex. `eth0`, `en0`). Om det inte anges används systemets standardgränssnitt.
- `--syn-threshold`: Minsta antal SYN-paket skickade av en IP för att betraktas som en SYN-flood (standard: `100`).
- `--syn-ratio`: Minsta tillåtna förhållande (kvot) mellan skickade SYN-paket och mottagna SYN-ACK-paket för att utlösa larm (standard: `10.0`).
- `-o`, `--output-log`: Sökvägen till loggfilen där varningar sparas (standard: `ids_alerts.log`).

---

## Web-baserat IDS-Dashboard

Verktyget innehåller även ett modernt, web-baserat användargränssnitt (Dashboard) byggt med FastAPI och WebSockets för realtidsvisualisering.

### Starta Dashboard-servern

Eftersom verktyget utför live-sniffning direkt från nätverkskortet krävs root-privilegier (`sudo`) på Unix-system för live-detektion. För att starta servern och använda den virtuella miljöns installerade beroenden, kör:

```bash
sudo ./.venv/bin/python3 src/web_ui.py
```

*(Om du har installerat beroendena globalt eller i ditt systems Python-miljö kan du köra med `sudo python3 src/web_ui.py`)*

> [!NOTE]
> Om du bara vill granska dashboardens layout, testa API:erna eller konfigurera inställningar utan att faktiskt starta den fysiska live-sniffningen (som kräver nätverkskortåtkomst), kan du köra servern helt utan `sudo`:
> ```bash
> python3 src/web_ui.py
> ```

### Öppna i Webbläsaren

När servern har startat kan du öppna gränssnittet i din webbläsare på:

[http://localhost:8000](http://localhost:8000)

### Funktioner i Dashboarden

Visualiseringsverktyget erbjuder följande funktioner i realtid:
* **Live-paketräknare**: Visar det totala antalet bearbetade nätverkspaket.
* **Tjänsteövervakning (Service Monitoring)**: Enkel och stilren lista som dynamiskt visar nätverksaktivitet för kända tjänster (t.ex. TikTok, YouTube, Spotify, LinkedIn, Telegram, etc.). Aktiviteten beräknas live genom DNS-mappning, och tjänster visas först när trafik detekteras.
* **Live-alarmlogg**: Visar realtidsdetekterade hot (SYN-floods, ARP-spoofing, DNS-tunnling, brute-force) med detaljerad information om käll-IP och attackmönster. Genom att klicka på ett larm visas en modal som förklarar hotet samt ger konkreta brandväggskommandon (`iptables` / `pfctl`) för blockering.
* **Aktivitetslista för värdar (Active Hosts)**: Visar upptäckta IP-adresser på nätverket och markerar omedelbart angripande värdar som "Suspicious".
* **Inställningar i realtid (Settings Drawer)**: Möjliggör direkt justering av detektionskriterier via webbgränssnittet.

---

## Köra Tester

Projektet har en komplett testsvit med 22 enhets- och integrationstester skriven i `pytest` för att säkerställa högsta kodkvalitet och korrekthet.

Med aktiverad virtuell miljö, kör:

```bash
pytest -v
```

Eller direkt via sökvägen till venv-pytest:

```bash
./.venv/bin/pytest -v
```

