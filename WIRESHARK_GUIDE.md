# Wireshark Guide: Generera en Test-PCAP för Intrusion Detection System (IDS)

Denna guide beskriver steg för steg hur du kan generera nätverkstrafik för att testa projektets detektionsskript för portskanningar och SYN-Flood DoS. Guiden täcker hur du använder Wireshark för att spela in trafiken och hur du simulerar angrepp med verktyg som `nmap` och `hping3`.

---

## 1. Förbered Wireshark för att Fånga Paket

För att spela in nätverkstrafik behöver du ha Wireshark installerat på din maskin.

1. **Starta Wireshark**: Öppna applikationen på ditt system.
2. **Välj Nätverksgränssnitt**:
   - Välj det gränssnitt som du ska använda för att skicka eller ta emot trafiken (t.ex. `Wi-Fi` eller `Ethernet`).
   - Om du testar lokalt mot din egen maskin (localhost), välj `Loopback` (ofta kallat `lo` eller `Adapter for loopback traffic capture` på Windows).
3. **Starta Fångsten (Capture)**:
   - Dubbelklicka på gränssnittet eller klicka på den **blå fenan** i det övre växstra hörnet för att börja spela in paket i realtid.

---

## 2. Simulera en Portskanning med `nmap`

En portskanning utförs för att identifiera öppna portar på en måldator. Detektionen triggas om en och samma käll-IP skannar fler unika destinationsportar än tröskelvärdet (standard: 20 unika portar) inom ett tidsfönster (standard: 5 sekunder).

För att simulera detta, öppna en terminal och kör följande kommando:

```bash
# Ersätt <IP> med din måldators IP-adress (t.ex. 127.0.0.1 för loopback)
# Flaggan -sS utför en TCP SYN-skanning (halvöppen skanning)
# Flaggan -p 1-1000 anger portintervallet 1 till 1000
nmap -sS -p 1-1000 <IP>
```

> [!TIP]
> Om du vill testa med en UDP-portskanning kan du istället använda:
> `sudo nmap -sU -p 1-50 <IP>`

---

## 3. Simulera en SYN Flood Attack med `hping3`

En SYN Flood är en Denial-of-Service (DoS) attack där angriparen skickar en ström av TCP SYN-paket till målet utan att svara på de SYN-ACK-paket som målet skickar tillbaka. Detta överbelastar målets anslutningskö.

För att simulera en SYN Flood, använd verktyget `hping3` (kräver vanligtvis administratörsrättigheter/root):

```bash
# Ersätt <IP> med din måldators IP-adress (t.ex. 127.0.0.1 för loopback)
# Flaggan -S anger att TCP SYN-flaggan ska vara satt
# Flaggan -p 80 anger att trafiken skickas till port 80
# Flaggan --flood skickar paket så snabbt som möjligt utan att vänta på svar
sudo hping3 -S -p 80 --flood <IP>
```

> [!WARNING]
> Kör endast detta kommando i en kontrollerad testmiljö mot system du har tillåtelse att testa. Stoppa kommandot efter några sekunder (med `Ctrl + C`) så att du inte överbelastar nätverket eller måldatorn och för att inte generera en alltför stor PCAP-fil.

---

## 4. Spara Trafiken som en `.pcap`-fil i Wireshark

När du har utfört simuleringarna ovan är det dags att spara den inspelade trafiken så dat IDS-skriptet kan analysera den.

1. **Stoppa Fångsten**: Klicka på den röda stoppknappen (fyrkanten) i Wireshark.
2. **Spara filen**:
   - Gå till **File** > **Save As...** (eller **Export Specified Packets...** om du vill spara enbart en specifik del av trafiken).
3. **Välj Format**:
   - I rullistan för filformat, välj **Wireshark/tcpdump/... - pcap** (`*.pcap`).
   - *Viktigt*: Spara som standard `.pcap`-format (ej `.pcapng`) för att säkerställa full kompatibilitet med Scapys `PcapReader` utan extra konverteringssteg, även om skriptet stöder standardläsning.
4. **Ange Filnamn**: Spara filen som exempelvis `capture.pcap` i din projektkatalog eller valfri lämplig sökväg.

Nu är din test-PCAP-fil redo att analyseras med hjälp av CLI-verktyget!
