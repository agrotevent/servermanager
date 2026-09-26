# RouterOS (CHR) über die API

Unter **Infrastruktur → RouterOS** werden MikroTik-Router mit RouterOS 7 – typischerweise ein
**Cloud Hosted Router (CHR) mit öffentlicher IP** – über die REST-API verwaltet: DHCP und Leases, NAT,
Routing/Mangle, DNS, Überwachung und eine **Konfigurationsanalyse** für bereits laufende Router.

## Zielbild

```
Internet ── WAN (öffentliche IP) ── RouterOS/CHR ── LAN-Bridge (DHCP) ── LXC mit Newt ──► Pangolin
                                                                   └── weitere Dienste (Nextcloud, …)
```

- Die Dienste im LAN erhalten ihre Adressen per **DHCP** vom RouterOS.
- Sie kommen per **NAT (masquerade)** auf dem WAN-Interface ins Internet; optional mit
  **Policy-Routing** (Mangle-Markierung + eigene Routing-Tabelle), damit z. B. ein WireGuard-Tunnel mit
  weiten AllowedIPs den Internetverkehr nicht „einsaugt“ und Antworten auf eingehende WAN-Verbindungen
  wieder über WAN gehen.
- Veröffentlicht werden die Dienste über **Pangolin**: der Newt-Client im LXC baut den Tunnel
  ausgehend auf – Portweiterleitungen sind dafür nicht nötig (siehe [Pangolin](pangolin.md)).

## Verbindung einrichten

Auf dem Router einen eigenen Benutzer anlegen (Zugriff nur aus dem Management-Netz):

```
/user group add name=servermanager policy=read,write,api,rest-api,test,!ftp,!ssh,!winbox,!telnet,!web,!sniff,!sensitive,!password,!policy,!reboot,!local,!romon
/user add name=servermanager group=servermanager address=10.66.0.0/24 password="…"
```

- `read` genügt für Überwachung und Analyse, `write` für Änderungen, `test` für den Ping-Test.
- Für die automatische Sicherung vor Änderungen (`/system backup save`) werden zusätzlich `ftp` und
  `sensitive` benötigt – sonst beim Anwenden „ohne Sicherung“ wählen und vorher selbst sichern.
- Der Dienst `www-ssl` muss aktiv sein (REST über https). Das meist selbstsignierte Zertifikat wird im
  Formular per **Abrufen** gepinnt.

Dann **Router hinzufügen**: REST-Adresse (z. B. `https://10.66.0.1`), Benutzer, Passwort.

**Einfacher:** beim Hinzufügen den vorhandenen Admin-Zugang eintragen und **eigenen API-Benutzer
anlegen** anhaken. Der Servermanager legt dann den Benutzer `servermanager` mit zufälligem Passwort an,
beschränkt auf die angegebenen Adressen, und speichert nur diesen – das Admin-Passwort wird nur einmal
verwendet. Dasselbe geht nachträglich unter *Bearbeiten → API-Benutzer per Admin-Anmeldung*.

Vor dem Speichern wird die Anmeldung geprüft. Schlägt sie fehl, wird nichts gespeichert und die
Ursachen werden angezeigt (mit **Trotzdem speichern** lässt sich das übergehen).

**Erlaubte Adressen:** RouterOS prüft die Absenderadresse, mit der der Servermanager ankommt. Das
Formular schlägt die dafür erkannte Adresse vor. Solange die interne Anbindung (WireGuard, Management-Netz)
noch nicht steht, ist das die öffentliche IP des Management-Servers – diese dann vorübergehend zusätzlich
erlauben und später unter *Bearbeiten → API-Benutzer* auf das Management-Netz einschränken.

## Reiter

| Reiter | Inhalt | Aktionen |
|---|---|---|
| Geräte | alle Geräte im Netz (DHCP-Leases + ARP) mit Lease-Art, Portfreigaben und zugehörigem System | Lease statisch machen, als System anlegen |
| Übersicht | CPU, RAM, Laufzeit, Interfaces mit Traffic, Adressen, Routen | Ping-Test vom Router (optional mit LAN-IP als Quelle – prüft NAT/Policy-Routing) |
| DHCP | Leases, Server, Netze | Lease **statisch machen**, statische Lease anlegen/löschen |
| NAT | alle NAT-Regeln | aktivieren/deaktivieren, Portweiterleitung anlegen, löschen |
| Routing & Mangle | Routing-Tabellen, -Regeln, Mangle, statische Routen | Route anlegen/löschen |
| Firewall | Filter je Kette, Adresslisten | nur Anzeige (Änderungen als Skript über die Analyse) |
| DNS | Server, statische Einträge | Eintrag anlegen/löschen |
| Konfigurationsanalyse | siehe unten | Änderungen anwenden, Skript herunterladen |

Vom Servermanager angelegte Einträge tragen den Kommentar `servermanager: …` (Markierung „SM“).

## Konfigurationsanalyse (bestehender Router)

Für einen **bereits laufenden** RouterOS prüft die Analyse, was bleiben kann und was geändert werden
muss:

1. **Konfiguration einlesen** – direkt über die API oder offline durch Einfügen/Hochladen der Ausgabe
   von `/export hide-sensitive`.
2. **Sollwerte** – werden aus der vorhandenen Konfiguration erkannt und können angepasst werden:
   WAN-Interface, LAN-Bridge und -Adresse, DHCP-Bereich, DNS, NTP, Management-Adressen, Name der
   Routing-Tabelle, Policy-Routing und MSS-Clamping ein/aus.
3. **Ergebnis** – je Punkt *Bleibt so*, *Anpassen*, *Fehlt* oder *Prüfen/Hinweis*, mit Ist-Zustand und
   dem passenden RouterOS-Befehl.

Geprüft werden u. a.:

- RouterOS-Version, Identität, NTP
- WAN mit öffentlicher Adresse, Default-Route
- LAN-Bridge, Adresse, Pool, DHCP-Server und -Netz (Gateway/DNS), dynamische Leases
- Upstream-DNS, DNS für Clients (allow-remote-requests) und offener Resolver
- NAT: Masquerade für das LAN über WAN, Masquerade ohne Ausgangs-Interface, vorhandene Portweiterleitungen
- Policy-Routing: Routing-Tabelle, Default-Route in der Tabelle, Adressliste lokaler Netze,
  Verbindungs- und Routing-Markierungen, **FastTrack** (umgeht Mangle-Markierungen), fremde Markierungen,
  MSS-Clamping für WireGuard
- Firewall: Schutz der Input-Kette, Forward-Kette, Regeln, die ausgehenden LAN-Verkehr (Newt!) blockieren
- Dienste: unverschlüsselte Dienste (telnet, ftp, www, api), REST über https, Adressbeschränkung der
  Management-Dienste, Neighbor Discovery und MAC-Server auf WAN, Standardbenutzer `admin`
- Tunnel: WireGuard-Peers mit 0.0.0.0/0, Hinweise zu Newt/Pangolin

**Anwenden:** Punkte mit Häkchen setzt der Servermanager per API um. Dabei gilt:

- Es werden nur **ergänzende** bzw. unkritische Änderungen automatisch ausgeführt (Pool, DHCP, DNS,
  NTP, NAT-Masquerade, Routing-Tabelle/-Route, Adresslisten, Mangle-Regeln). Vorhandene Einträge werden
  nicht gelöscht.
- Vor dem Anwenden wird die Konfiguration **live neu gelesen** (nie ein älterer Import) und auf dem
  Router eine Sicherung `sm-before-<Zeit>.backup` (plus Export) angelegt.
- **Firewall-, Dienst- und Benutzeränderungen gibt es nur als Skript** („Alle Änderungen als
  Skript (.rsc)“) – sie können den Zugang sperren und müssen bewusst geprüft und eingespielt werden.
  Wichtig: die eigene Management-Adresse in die Liste `sm-mgmt` aufnehmen und die Reihenfolge der
  Regeln prüfen (`place-before`).
- Alles wird im Audit-Log protokolliert (`router.apply`).

## Überwachung

Der Worker fragt die Router regelmäßig ab (Intervall wie bei Proxmox). Warnungen: API nicht
erreichbar, CPU-Last oder RAM ≥ 90 %.
