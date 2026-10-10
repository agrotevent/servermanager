# Bestand übernehmen & Optimierungen

Vorhandene Infrastruktur wird schrittweise in den Servermanager übernommen: erst **Schnittstellen und
Datenimport**, dann **Management-Zugänge**, dann **Optimierungen** – jede Änderung erst nach Anzeige
und Bestätigung.

## Zielbild

Von außen ist möglichst nur noch **eine öffentliche IP** nötig. Dienste werden über Pangolin-Tunnel
erreichbar gemacht – mit einem **Backup-Weg** über einen zweiten Pangolin-Server:

```
                 Internet
        ┌───────────┴────────────┐
  Pangolin A (primär)     Pangolin B (Backup-Weg)
        ▲  Tunnel (ausgehend)      ▲  Tunnel (ausgehend)
        │                          │
  ┌─────┴──── Proxmox-Host 1 ──┐ ┌─┴──── Proxmox-Host 2 ──────┐
  │ LXC newt-a                  │ │ LXC newt-b                 │
  │ LXC/VM Dienste …            │ │ LXC/VM Dienste …           │
  └─────────────┬───────────────┘ └────────────┬───────────────┘
                └──── gemeinsames Netz ────────┘
        (Hetzner: vSwitch-VLAN, MTU 1400 · lokal: gemeinsames LAN)
                         │
                 RouterOS / CHR (öffentliche IP, DHCP, NAT)
```

- Die Newt-Container von primärem und Backup-Pangolin laufen auf **verschiedenen Proxmox-Hosts**, damit
  beim Ausfall eines Hosts ein Weg erhalten bleibt.
- **Hetzner:** Die Hosts sind über einen vSwitch (VLAN 4000–4091, MTU 1400) verbunden, sodass lokale IPs
  zwischen den Hosts funktionieren. **Lokal:** Die Hosts hängen in einem gemeinsamen Netz.
- Portfreigaben auf der öffentlichen IP werden durch Pangolin-Veröffentlichungen ersetzt. **Ausnahme:**
  Mailcow bekommt für IMAP/SMTP eine eigene Public-IP (siehe [Nextcloud, Mailcow & SSO](apps.md)).

## 1. Schnittstellen anbinden und Daten importieren

| Gerät | Anbindung | Import |
|---|---|---|
| Proxmox | Verbindung anlegen, Zertifikat pinnen, Token (siehe unten) | Gäste mit Status, IP, MAC, Bridge, Guest-Agent; Abgleich mit vorhandenen Systemen |
| RouterOS | Verbindung anlegen, API-Benutzer (siehe unten) | Konfiguration (Analyse), Geräte im Netz aus DHCP und ARP, Portfreigaben |
| Pangolin | Verbindung mit API-Schlüssel, Rolle primär/Backup | Sites, veröffentlichte Dienste und ihre Ziele (*Pangolin → Alle Veröffentlichungen*) |

Das Einlesen ändert nichts an den Geräten.

## 2. Management-Zugänge anlegen

- **Proxmox-API:** *Proxmox → Bearbeiten → Management-Zugang per Admin-Anmeldung*: einmalige Anmeldung
  (z. B. `root@pam`, optional mit 2FA-Code). Angelegt werden der Benutzer `servermanager@pve` und ein
  API-Token. Das Passwort wird nicht gespeichert und erst nach Prüfung des gepinnten Zertifikats
  übertragen. Alternativ per SSH über den verknüpften Host.
- **RouterOS:** *RouterOS → Bearbeiten → API-Benutzer per Admin-Anmeldung*: legt Gruppe und Benutzer
  `servermanager` mit zufälligem Passwort an, beschränkt auf die Management-Adressen.
- **Bestehende Container und VMs:** *Proxmox → Bestand übernehmen*. Der SSH-Schlüssel des
  Servermanagers wird über einen vertrauenswürdigen Weg hinterlegt:
  - **Container (LXC):** per `pct exec` über den Proxmox-Host. Dafür muss der Host als System (SSH)
    verknüpft sein. Im Cluster wird der Befehl über die Cluster-SSH-Verbindung auf dem richtigen Node
    ausgeführt.
    - Ist der Host noch kein System: *Proxmox → Verbindung → Proxmox-Host als System anlegen*.
      Name, Adresse (aus der API-Adresse) und Typ Proxmox sind vorbelegt. Root-Passwort eintragen und
      speichern. Der Servermanager installiert seinen SSH-Schlüssel, entfernt das Passwort wieder und
      verknüpft das System mit der Verbindung.
    - Ist der Host schon ein System, verknüpft ihn die Übernahme selbst, wenn er eindeutig ist: gleiche
      Adresse oder gleicher DNS-Name wie die API (auch `hostname -f` aus der Erstprüfung), die
      aufgelöste Adresse des API-Namens oder ein Proxmox-System mit dem Kurznamen des Nodes. Sonst unter
      *Bearbeiten → Verknüpfungen* wählen.
  - **VMs:** über den QEMU-Guest-Agent (in der VM installiert und in den VM-Optionen aktiviert).
  - Die **SSH-Hostkeys** werden auf demselben Weg gelesen und fest hinterlegt – schon die erste
    SSH-Verbindung ist geprüft.
  - Optional wird ein fehlender SSH-Server installiert (Debian/Ubuntu, Alpine, RHEL-Familie).
  - Danach wird das System aufgenommen, dem Gast zugeordnet und seine Komponenten erkannt.
  - Schlägt ein Gast fehl (z. B. SSH danach nicht erreichbar), wiederholt **Wiederholen** im Job nur
    die fehlgeschlagenen Gäste. Gäste, deren System nicht online ist, lassen sich in *Bestand
    übernehmen* erneut auswählen (Kennzeichen „Einrichtung wiederholen“), einzelne Systeme auch über
    **Einrichtung wiederholen** auf der System-Seite.
- **Geräte ohne Proxmox** (z. B. aus der Geräteliste des Routers): *Als System* öffnet das normale
  Formular mit IP und Name vorausgefüllt.

## 3. Optimierungen

*Infrastruktur → Optimierungen* (nur Administratoren):

1. **Jetzt scannen** liest Proxmox, RouterOS und Pangolin ein (als Job, ändert nichts).
2. Die Vorschläge erscheinen nach Bereichen – *kritisch*, *empfohlen* oder *Hinweis*. Punkte mit
   Kästchen kann der Servermanager umsetzen, *manuell* markierte nicht (Grund steht dabei).
3. Auswählen, ggf. Eingaben ergänzen (z. B. Subdomain) → **Auswahl prüfen** zeigt genau, was passiert →
   **Jetzt umsetzen** startet einen Job. Jeder Punkt wird unmittelbar vorher erneut geprüft; ein Fehler
   stoppt die übrigen nicht. Alles steht im Job-Protokoll und im Audit-Log.

| Bereich | Vorschläge (Auswahl) | Umsetzung |
|---|---|---|
| Ziel: eine Public-IP | Portfreigabe über Pangolin veröffentlichen; ersetzte Portfreigabe deaktivieren; Verwaltung über öffentliche IP | Veröffentlichung auf dem primären Pangolin; NAT-Regel deaktivieren (nur wenn der Dienst wirklich über Pangolin erreichbar ist) |
| Tunnel & Ausfallsicherheit | kein Backup-Weg; Dienst ohne Backup-Weg; Site offline; Newt gestoppt; **beide Tunnel auf demselben Host**; Tunnel-Container nicht überwacht | Spiegeln auf den Backup-Pangolin; Newt neu starten; Container auf einen anderen Node migrieren; Überwachung einschalten |
| Proxmox | Autostart fehlt; Guest-Agent aus; privilegierter Container; in keinem Sicherungsjob; Disk voll; Gast nicht verwaltet; **vSwitch nicht eingebunden**, MTU ≠ 1400 im vSwitch | Konfiguration setzen; Sicherungsjob „servermanager“ (02:30, Snapshot, 7 täglich/4 wöchentlich); Disk vergrößern; Bestand übernehmen; VLAN-Interface + Bridge anlegen und aktivieren |
| RouterOS | Ergebnisse der Konfigurationsanalyse (NAT, Policy-Routing, DHCP, DNS …); genutzte IP mit dynamischer Lease | nur unkritische, ergänzende Änderungen mit Sicherung vorab; Firewall/Dienste nur als Skript |
| Pangolin | Dienst ohne Anmeldung | Pangolin-Anmeldung aktivieren |
| Anwendungen | Weboberfläche von authentik, Mailcow oder SSO-verbundener Nextcloud nicht veröffentlicht; Mail-IP von Mailcow nicht eingerichtet; DNS für Mailversand | Veröffentlichung ohne Pangolin-Anmeldung; IP am WAN, Mail-Ports weiterleiten, Source-NAT vor Masquerade |

Liegen die Newt-Container beider Pangolin-Server auf demselben Host:

- **Im Cluster:** Der Servermanager schlägt vor, den Backup-Tunnel auf den Node mit der geringsten
  Auslastung zu migrieren.
- **Ohne weiteren Node:** Den Backup-Tunnel auf einem anderen Proxmox-Host neu anlegen (siehe
  [Pangolin](pangolin.md)).
