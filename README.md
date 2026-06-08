# Nätverksanalys & Intrusion Detection System (IDS)

Hej! Det här är mitt projekt för nätverkssäkerhet i praktiken. Det är ett Python-baserat IDS-verktyg som analyserar nätverkstrafik (antingen live direkt från nätverkskortet eller genom att läsa in en sparad `.pcap`-fil) för att upptäcka misstänkt aktivitet. Larmen sparas i en lokal loggfil och visas i realtid på ett schysst webb-dashboard.

---

## Vad verktyget gör (Detektionsmotorer)

Jag har byggt in 4 detektionsregler baserade på Scapy för att upptäcka vanliga attacker:

1. **SYN-Flood DoS**: Om en IP-adress skickar jättemånga TCP SYN-paket men knappt får några SYN-ACK tillbaka, flaggas det som ett överbelastningsförsök.
2. **ARP-Spoofing**: Håller koll på IP- till MAC-adresser. Om en IP-adress plötsligt dyker upp med flera olika MAC-adresser i nätverket varnar systemet för en Man-in-the-Middle (MitM) attack.
3. **DNS-Tunneling**: Upptäcker om någon försöker smuggla ut data via DNS genom att kolla på längden på DNS-frågorna. Om en IP-adress skickar många extremt långa subdomänförfrågningar triggas larmet.
4. **Brute-Force & Portskanning**: Hittar upprepade anslutningsförsök (TCP SYN) från en käll-IP under kort tid (t.ex. 20 anslutningar på 10 sekunder), vilket brukar tyda på skanning eller brute-force.

---

## Hur projektet är uppbyggt

Här är filerna jag har lagt till:
* **`src/`**
  * `analyzer.py`: Själva detektionsmotorn som processar paketen och kör logiken för reglerna.
  * `web_ui.py`: FastAPI-servern och WebSockets för dashboarden i webbläsaren.
  * `cli.py`: CLI-gränssnittet om man vill köra via terminalen och analysera PCAP-filer direkt.
* **`tests/`**: Mina enhetstester och integrationstester (totalt 23 stycken) för att säkerställa att allt fungerar.
* **`services.json`**: En lista med kända tjänster (som YouTube, Netflix, Spotify) för att automatiskt namnge trafiken baserat på DNS.
* **`WIRESHARK_GUIDE.md`**: En liten guide jag skrev om hur man genererar test-PCAP-filer med Wireshark/nmap/hping3.

---

## Installation & Körning

Verktyget kräver Python 3.12+.

1. Skapa en virtuell miljö:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # (eller .venv\Scripts\activate.bat på Windows)
   ```
2. Installera paketen:
   ```bash
   pip install -r requirements.txt
   ```

### Köra i terminalen (CLI)
För att analysera en sparad PCAP-fil:
```bash
python3 src/cli.py din-fil.pcap
```
För live-sniffning direkt från nätverkskortet (kräver `sudo` på macOS/Linux för att läsa råa paket):
```bash
sudo python3 src/cli.py --live
```
Du kan också anpassa gränsvärden, t.ex:
```bash
python3 src/cli.py din-fil.pcap --syn-threshold 50 --syn-ratio 5.0 -o mina_larm.log
```

### Köra Webb-Dashboarden
För att starta webbservern:
```bash
sudo ./.venv/bin/python3 src/web_ui.py
```
*(Om du bara vill testa UI:t utan live-sniffing kan du starta utan `sudo`: `python3 src/web_ui.py`)*

#### Säkerhetsinställningar
Eftersom servern körs som root via `sudo` har jag begränsat den till att bara lyssna på **localhost** (`127.0.0.1`) som standard för att ingen annan på nätverket ska kunna köra kommandon.
Om du kör på ett säkert nätverk och vill nå den utifrån kan du ändra host och port:
```bash
sudo ./.venv/bin/python3 src/web_ui.py --host 0.0.0.0 --port 8000
```
Sedan är det bara att öppna [http://localhost:8000](http://localhost:8000) i webbläsaren.

---

## Tester
Mina tester körs enkelt med `pytest`:
```bash
pytest -v
```
