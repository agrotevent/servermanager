# Hetzner Root- und Cloud-Server

Unter *Infrastruktur → Hetzner* stehen beide Arten von Hetzner-Servern nebeneinander:

- **Root-Server (dediziert)** über den Robot-Webservice.
- **Cloud-Server** über die Hetzner-Cloud-API.

Rechte und Bedienung sind gleich aufgebaut.

## Root-Server (Robot)

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
- **vSwitches** des Kontos:
  - VLAN und angebundene Server samt Status der Anbindung, mit Warnung bei „fehlgeschlagen“.
  - Öffentliche IP-Netze des vSwitches und gekoppelte Cloud-Netze.
  - PTR-Einträge in diesen Netzen, setzbar mit *Ändern* am Konto.
  - Traffic der vSwitch-Netze für Monat und Jahr, soweit Hetzner dafür Werte liefert. Für viele
    vSwitch-Netze liefert die Robot-API keine. Dann steht das als Hinweis auf der Seite, und der
    Traffic der Server ist davon nicht betroffen.
  - Proxmox-Server mit demselben VLAN werden verlinkt.
  - Auf der Seite eines Servers stehen seine vSwitches als Übersicht.

### Einrichten

1. In der Hetzner Robot-Oberfläche unter *Einstellungen → Webservice- und App-Einstellungen* einen
   **Webservice-Benutzer** anlegen. Das ist nicht die Kundennummer und nicht der Robot-Login.
2. Im Servermanager *Infrastruktur → Hetzner → Hetzner-Konto anbinden*: Benutzer und Passwort
   eintragen. Alle Root-Server des Kontos werden sofort übernommen. Weitere Konten lassen sich genauso
   hinzufügen.

Das Passwort wird verschlüsselt gespeichert. Die Verbindung prüft das Zertifikat von Hetzner über die
System-CAs. Der Servermanager fragt Hetzner höchstens alle 15 Minuten ab, weil Hetzner die Zahl der
Anfragen begrenzt. Andere Zeiträume beim Traffic werden beim Aufruf live geholt. Wird die Grenze
erreicht, sagt die Meldung das.

## Cloud-Server

Für die Hetzner Cloud gibt es dieselbe Übersicht, je Projekt:

- **Status:** Server mit Typ, Standort, Image, Löschschutz und privaten Netzen. Das zugehörige System
  im Servermanager wird über die IP-Adresse erkannt.
- **IP-Adressen mit PTR:**
  - Primäre IPv4 und IPv6 sowie zugewiesene Floating-IPs.
  - PTR setzen, auch für beliebige Adressen aus dem IPv6-/64. Leer speichern stellt den
    Standardeintrag von Hetzner wieder her.
- **Traffic:** ausgehend und eingehend im laufenden Abrechnungszeitraum. Ab einem einstellbaren Anteil
  des Inklusiv-Traffics gibt es eine Warnung (Standard 90 %).
- **Auslastung:** CPU und öffentliches Netzwerk der letzten 24 Stunden, 7 Tage oder 30 Tage, aus den
  Messwerten der Hetzner Cloud.
- **Neustart und Energie:**
  - Sauberer Neustart und Herunterfahren (ACPI).
  - Reset und Ausschalten (hart, wie Stromtrennung).
  - Einschalten.
- **Servername** ändern.

### Einrichten

1. In der Hetzner Cloud Console das Projekt öffnen und unter *Sicherheit → API-Tokens* ein Token
   erzeugen.
   - **Lesen** reicht für die Auswertung.
   - Für Neustarts, PTR-Einträge und Umbenennen braucht das Token **Lesen & Schreiben**.
   - Jedes Projekt hat sein eigenes Token, mehrere Projekte lassen sich nebeneinander anbinden.
2. Im Servermanager *Infrastruktur → Hetzner → Cloud-Projekt anbinden*: Token eintragen. Alle Server
   des Projekts werden sofort übernommen.

Das Token wird verschlüsselt gespeichert. Abgefragt wird höchstens alle 15 Minuten, die Auslastung beim
Aufruf der Serverseite.

## Rechte

Rechte vergeben Administratoren unter *Benutzer*, entweder für ein **ganzes Robot-Konto bzw.
Cloud-Projekt** (alle seine Server, auch künftig hinzukommende) oder für **einzelne Server**. Gilt
beides, zählt die höhere Stufe.

| Stufe | erlaubt |
|---|---|
| Auswerten | Status, IP-Adressen und PTR-Einträge, Traffic und Warnungen ansehen |
| Neustarten | alles aus *Auswerten*, dazu Software- und Hardware-Reset, Ein-/Ausschalter, Wake-on-LAN; in der Cloud Neustart, Herunterfahren, Reset, Aus- und Einschalten |
| Ändern | alles aus *Neustarten*, dazu PTR-Einträge, Servername, Traffic-Warnungen (Robot) und der Reset durch einen Techniker (Robot) |

vSwitches gehören zum ganzen Konto: Ihre Seite sehen nur Benutzer mit Rechten auf das Konto, PTR-Einträge
in vSwitch-Netzen setzt, wer *Ändern* am Konto hat. Wer nur einen Server sehen darf, sieht auf dessen
Seite die angebundenen vSwitches mit VLAN und Netzen.

Konten und Projekte anlegen, bearbeiten und entfernen dürfen nur Administratoren. Jeder Reset und jede Änderung
steht mit Benutzer und Details im Audit-Log, ebenso ein fehlgeschlagener Reset.

## Zugriff über authentik

Hetzner Robot selbst bietet keine Anmeldung über einen fremden Anmeldedienst wie authentik. Stattdessen
führt authentik zu den Hetzner-Funktionen des Servermanagers. Die Robot-Zugangsdaten bleiben dabei
verschlüsselt im Servermanager, die Benutzer brauchen keine eigenen Hetzner-Zugänge. Voraussetzung ist
die [Anmeldung am Servermanager über authentik](benutzer.md#anmeldung-uber-authentik-sso).

Beides richten Administratoren unten auf der Hetzner-Seite unter *Zugriff über authentik* ein.

### Rechte über authentik-Gruppen

Eine authentik-Gruppe bekommt ein Recht (*Auswerten*, *Neustarten*, *Ändern*) auf ein Ziel:

- ein Robot-Konto (alle Root-Server),
- einen einzelnen Root-Server,
- ein Cloud-Projekt (alle Cloud-Server),
- einen einzelnen Cloud-Server.

Den Gruppennamen schlägt das Eingabefeld aus authentik vor. Groß- und Kleinschreibung spielen keine
Rolle.

So wirkt es:

- **Gruppen kommen bei jeder Anmeldung aus authentik.** Meldet sich ein Benutzer über authentik an,
  übernimmt der Servermanager seine Gruppen und gibt ihm die zugeordneten Rechte. Wer in authentik aus
  der Gruppe entfernt wird, verliert das Recht mit der nächsten Anmeldung. Sitzungen enden nach der
  eingestellten Sitzungsdauer.
- **Bei einer Anmeldung mit Passwort entfallen die Gruppen.** Rechte über Gruppen gelten nur für die
  Anmeldung über authentik.
- **Eigene Rechte zählen weiter.** Hat der Benutzer zusätzlich eigene Rechte (unter *Benutzer*), gilt
  die höhere Stufe.
- **Neue Benutzer:** Ist unter SSO *Unbekannte Benutzer anlegen* aktiv, entsteht das Konto beim ersten
  Login automatisch. Die Gruppe genügt dann für den Zugriff.

Welche Gruppen ein Benutzer zuletzt mitgebracht hat, steht unter *Benutzer → (Benutzer)*.

### Kachel im authentik-Portal

*Kachel in authentik anlegen* legt in authentik die Anwendung **Hetzner** an. Sie hat keinen Provider,
sondern nur eine Start-Adresse.

- **Klick auf die Kachel:** Sie meldet den Benutzer über authentik am Servermanager an
  (`/login/sso?next=/hetzner/`) und öffnet direkt die Hetzner-Seite. Ist er schon angemeldet, geht es
  sofort weiter.
- **Sichtbarkeit:** Mit *Nur für Mitglieder der zugeordneten Gruppen sichtbar* (Standard) bindet der
  Servermanager die Anwendung in authentik an die Gruppen aus *Rechte über authentik-Gruppen*. Nur deren
  Mitglieder sehen die Kachel.
  - Ändern sich die Zuordnungen, passt er die Bindungen automatisch an.
  - Gruppen, die es in authentik nicht gibt, meldet er.
  - Ohne zugeordnete Gruppe ist die Kachel für alle sichtbar.
- **Entfernen** löscht die Anwendung samt Bindungen aus authentik.

Voraussetzung ist die öffentliche URL des Servermanagers (*Einstellungen → Allgemein*).

## Fehlerbehebung

- **„Anmeldung fehlgeschlagen – Webservice-Benutzer prüfen“:** Die Daten müssen vom
  Webservice-Benutzer stammen (beginnt meist mit `#ws+`), nicht vom Robot-Login.
- **„Hetzner begrenzt die Anfragen“:** Einige Minuten warten. Resets sind bei Hetzner besonders knapp
  bemessen.
- **„Ungültige Eingabe (subnet)“ beim Traffic** (bis Version 1.16.0): Subnetze wurden mit Präfixlänge
  abgefragt. Ab 1.16.1 wird nur die Netzadresse übergeben. Lehnt Hetzner ein einzelnes Subnetz
  trotzdem ab, werden die übrigen Adressen ausgewertet, und der Hinweis nennt das fehlende Subnetz.
- **Server fehlt:** Er gehört zu einem anderen Robot-Konto bzw. Cloud-Projekt. Cloud-Server werden über
  ein Cloud-Projekt angebunden, nicht über das Robot-Konto.
- **Cloud: „für Neustarts und Änderungen braucht das Token Lesen & Schreiben“:** In der Cloud Console ein
  neues Token mit Schreibrecht erzeugen und beim Projekt eintragen.
- **Cloud: „API-Token ungültig oder gelöscht“:** Das Token wurde in der Console entfernt oder gehört zu
  einem anderen Projekt.
