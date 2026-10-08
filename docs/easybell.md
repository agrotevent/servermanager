# easybell Cloud Telefonanlage

Der Servermanager bindet die easybell Cloud Telefonanlage über ihre offizielle Programmierschnittstelle an,
das **Asterisk Manager Interface (AMI)**. Eine öffentliche REST-API für Kunden dokumentiert easybell nicht.
Über AMI funktionieren:

- **Endgeräte:** registrierte Telefone und Softphones mit Status; optional eine Warnung, wenn eines
  nicht erreichbar ist.
- **Laufende Gespräche:** Stand beim letzten Abruf.
- **Anrufjournal:** jeder ein- und ausgehende Anruf mit Rufnummern, angenommen von, Dauer und Ergebnis
  (verpasst, besetzt …), Filter und Suche, Aufbewahrung einstellbar (Standard 30 Tage).
- **Anrufe in Zammad:** Anruferkennung (Pop-up), Anrufliste und Kundenzuordnung über die
  Zammad-Integration „CTI (generisch)“.

## Einrichten

1. In **my.easybell** die Cloud Telefonanlage öffnen und unter *Erweiterte Einstellungen →
   Integration* die **AMI-Schnittstelle** aktivieren. easybell zeigt dann Benutzername und Passwort an.
2. In die **IP-Freigabeliste** die **öffentliche IP-Adresse** eintragen, mit der der Servermanager ins
   Internet geht (z. B. die Public-IP des Routers).
3. Im Servermanager *Infrastruktur → easybell → easybell anbinden*: Name, Benutzername und Passwort
   eintragen. Server `jarvis.easybell.de` und Port `5039` sind vorbelegt.
4. Optional für Zammad: In Zammad unter *Admin → Integrationen → CTI (generisch)* die Integration
   aktivieren. Den angezeigten **Endpunkt** kopieren, beim easybell-Eintrag einfügen (oder nur das Token
   am Ende) und die Zammad-Verbindung auswählen. Nötig ist eine bereits angelegte
   [Zammad-Verbindung](zammad.md).

### Sicherheit der Verbindung

Port 5039 ist bei Asterisk der Port für **AMI über TLS**. Mit der Verbindungsart *automatisch*
(Standard) versucht der Servermanager zuerst TLS und prüft das Zertifikat gegen die System-CAs.
Antwortet der Server unverschlüsselt, nimmt er die unverschlüsselte Verbindung. Bei einem ungültigen
Zertifikat bricht er ab und weicht **nicht** auf unverschlüsselt aus. Welche Verbindung läuft, steht
auf der Detailseite (*TLS* bzw. *unverschlüsselt*). Mit *nur TLS* lässt sich die unverschlüsselte
Verbindung ganz ausschließen.

Zusätzlich gilt die IP-Freigabeliste. Das Passwort sendet der Servermanager nie: Die Anmeldung läuft
über die MD5-Challenge von AMI. Nur wenn der Server das nicht anbietet und Sie es ausdrücklich
erlauben, wird das Passwort im Klartext gesendet. Ohne TLS sind die Ereignisse, also Rufnummern,
unverschlüsselt unterwegs. Passwort und CTI-Token werden verschlüsselt gespeichert.

## Ereignis-Verbindung

Ist *Dauerhafte Ereignis-Verbindung* eingeschaltet, hält der Worker je Anlage eine Verbindung offen:

- Er schreibt Anrufe ins Journal und meldet sie an Zammad (`newCall`, `answer`, `hangup`).
- Nach einer Unterbrechung verbindet er sich automatisch neu, mit Wartezeiten von 5 Sekunden bis
  5 Minuten.
- Ist die Verbindung getrennt, steht das samt Grund auf der Detailseite und als Warnung im Dashboard.
- Änderungen an den Einstellungen übernimmt sie innerhalb einer Minute.

Über dieselbe Verbindung fragt der Servermanager alle 5 Minuten Endgeräte und laufende Gespräche ab.
easybell lässt je Zugang nur eine AMI-Verbindung zu, deshalb meldet er sich dafür nicht ein zweites Mal
an.

Die Richtung eines Anrufs erkennt der Servermanager am Kanal:

- Kanäle der eigenen Endgeräte heißen bei easybell `PJSIP/CPBX-…`. Ein Anruf, der dort beginnt, ist
  ausgehend.
- Ein Anruf, der woanders beginnt, ist eingehend.
- Weicht die Benennung ab, lässt sich das Muster in den Einstellungen anpassen (regulärer Ausdruck).

Rufnummern werden international ohne `+` gespeichert und gemeldet, zum Beispiel `4930123456`, so wie
Zammad sie erwartet. Die Ländervorwahl für nationale Nummern ist einstellbar.

## Rechte

| Stufe | erlaubt |
|---|---|
| Lesen | Übersicht, Endgeräte, Gespräche und Anrufjournal ansehen |
| Bedienen | zusätzlich sofort aktualisieren |
| Vollzugriff | (Anlegen, Bearbeiten und Entfernen nur für Administratoren) |

Das Anrufjournal enthält personenbezogene Daten (Rufnummern). Vergeben Sie das Leserecht deshalb gezielt
und wählen Sie die Aufbewahrung nicht länger als nötig.

## Fehlerbehebung

- **„Verbindung steht, aber keine Begrüßung vom Server“** (früher „Zeitüberschreitung beim Lesen“):
  easybell nimmt die Verbindung an, meldet sich aber nicht. Mögliche Ursachen:
  - Port 5039 erwartet TLS, die Verbindungsart steht aber auf *unverschlüsselt*. *Automatisch* oder
    *nur TLS* wählen. Bis Version 1.17.3 konnte der Servermanager kein TLS, das war die
    wahrscheinlichste Ursache.
  - Die öffentliche IP des Servermanagers fehlt in der IP-Freigabeliste.
  - Die AMI-Schnittstelle ist nicht aktiviert.
  - Der Zugang ist bereits verbunden: easybell erlaubt je Zugang nur eine AMI-Verbindung. Ein anderes
    Programm mit denselben Zugangsdaten (z. B. eine CTI-Software) blockiert dann den Servermanager.

  Solange die Ereignis-Verbindung des Servermanagers steht, fragt er Endgeräte und Gespräche über
  genau diese Verbindung ab (alle 5 Minuten) und öffnet keine zweite. Ab 1.28.1 gilt das auch, während
  sie sich neu verbindet. Bis dahin öffnete die Status-Abfrage dann eine zweite Verbindung, und beide
  blockierten sich gegenseitig mit genau dieser Meldung.

  **Öffentliche IP ermitteln** (oben auf der Seite) zeigt die Adresse, mit der der Servermanager ins
  Internet geht. Sie muss in der IP-Freigabeliste stehen. Abgefragt wird sie nur auf Klick bei
  `api.ipify.org`. Bei mehreren öffentlichen IPs am Router (z. B. eine eigene Mail-IP) ist es die
  Adresse der Standard-Route, nicht die der Mail-IP.

- **„keine Antwort – ist die öffentliche IP … in der IP-Freigabeliste eingetragen?“:** easybell
  verwirft Verbindungen von nicht freigegebenen Adressen kommentarlos. Die Public-IP prüfen, mit der
  der Servermanager ins Internet geht (z. B. `curl -4 ifconfig.me` auf dem Servermanager).
- **„AMI-Anmeldung fehlgeschlagen“:** Benutzername und Passwort aus den erweiterten Einstellungen
  erneut kopieren. Beim Deaktivieren und Wiederaktivieren der Schnittstelle vergibt easybell ein neues
  Passwort.
- **„keine Berechtigung“ bei Endgeräten oder Gesprächen:** Der Zugang darf diese Abfrage nicht
  ausführen. Journal und Zammad funktionieren trotzdem, weil sie nur Ereignisse brauchen.
- **Anrufe kommen nicht in Zammad an:** Prüfen, ob in Zammad *CTI (generisch)* aktiv ist und das Token
  passt. Auf der Übersicht zeigt der Servermanager, wie viele Meldungen fehlgeschlagen sind, im Journal
  steht es je Anruf.
