# Hetzner Root-Server

Der Servermanager steuert und wertet dedizierte Hetzner-Server über den **Robot-Webservice** aus
(`robot-ws.your-server.de`):

- **Übersicht:** alle Server eines oder mehrerer Robot-Konten mit Produkt, Rechenzentrum, Status,
  Kündigung, Traffic des laufenden Monats und dem zugehörigen System im Servermanager. Die Zuordnung
  läuft automatisch über die IP-Adresse.
- **IP-Adressen mit PTR-Einträgen:**
  - Haupt-IP, Zusatz-IPs und IPv6-Netz mit Reverse DNS.
  - PTR setzen oder löschen, auch für einzelne Adressen aus dem IPv6-/64 oder einem Subnetz.
  - Traffic-Warnungen je IPv4-Adresse: Hetzner schickt eine E-Mail, wenn eine Grenze pro Stunde, Tag
    oder Monat überschritten wird.
- **Traffic:**
  - Laufender Monat mit Tageswerten, ein beliebiger Monat der letzten 12 Monate oder ein ganzes Jahr
    mit Monatswerten.
  - Eingehend und ausgehend, als Summe aller Adressen des Servers.
  - Bei Servern mit Inklusivvolumen gibt es eine Warnung ab einem einstellbaren Prozentsatz (Standard
    90 %).
- **Neustart:** Software-Reset (Strg+Alt+Entf), Hardware-Reset, Ein-/Ausschalter (kurz und lang),
  Wake-on-LAN sowie ein manueller Reset durch einen Hetzner-Techniker. Angeboten wird nur, was Hetzner
  für den jeweiligen Server zulässt.
- **Servername** in Robot ändern.

## Einrichten

1. In der Hetzner Robot-Oberfläche unter *Einstellungen → Webservice- und App-Einstellungen* einen
   **Webservice-Benutzer** anlegen. Das ist nicht die Kundennummer und nicht der Robot-Login.
2. Im Servermanager *Infrastruktur → Hetzner → Hetzner-Konto anbinden*: Benutzer und Passwort
   eintragen. Alle Root-Server des Kontos werden sofort übernommen. Weitere Konten lassen sich genauso
   hinzufügen.

Das Passwort wird verschlüsselt gespeichert. Die Verbindung prüft das Zertifikat von Hetzner über die
System-CAs. Der Servermanager fragt Hetzner höchstens alle 15 Minuten ab, weil Hetzner die Zahl der
Anfragen begrenzt. Andere Zeiträume beim Traffic werden beim Aufruf live geholt. Wird die Grenze
erreicht, sagt die Meldung das.

## Rechte

Rechte vergeben Administratoren unter *Benutzer*, entweder für ein **ganzes Konto** (alle seine Server,
auch künftig hinzukommende) oder für **einzelne Server**. Gilt beides, zählt die höhere Stufe.

| Stufe | erlaubt |
|---|---|
| Auswerten | Status, IP-Adressen und PTR-Einträge, Traffic und Warnungen ansehen |
| Neustarten | alles aus *Auswerten*, dazu Software- und Hardware-Reset, Ein-/Ausschalter, Wake-on-LAN |
| Ändern | alles aus *Neustarten*, dazu PTR-Einträge, Servername, Traffic-Warnungen und der Reset durch einen Techniker |

Konten anlegen, bearbeiten und entfernen dürfen nur Administratoren. Jeder Reset und jede Änderung
steht mit Benutzer und Details im Audit-Log, ebenso ein fehlgeschlagener Reset.

## Fehlerbehebung

- **„Anmeldung fehlgeschlagen – Webservice-Benutzer prüfen“:** Die Daten müssen vom
  Webservice-Benutzer stammen (beginnt meist mit `#ws+`), nicht vom Robot-Login.
- **„Hetzner begrenzt die Anfragen“:** Einige Minuten warten. Resets sind bei Hetzner besonders knapp
  bemessen.
- **Server fehlt:** Er gehört zu einem anderen Robot-Konto oder ist ein Cloud-Server. Hetzner Cloud
  hat eine eigene API und wird hier nicht verwaltet.
