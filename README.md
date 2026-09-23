# Servermanager

Webbasiertes Werkzeug zur Verwaltung und Wartung von Linux-Servern – **Debian 12/13, Nextcloud,
Docker, ISPConfig und Proxmox VE** – über SSH, wahlweise durch ein **WireGuard-Management-Netz auf
einem MikroTik (RouterOS 7)** oder direkt per SSH für bestehende Systeme ohne Tunnel.

- Update-Übersicht: welches Gerät hat welche Aktualisierungen offen (Pakete, Sicherheitsupdates,
  Nextcloud-Core/Apps, Docker-Images, ISPConfig, Release-Upgrade 12 → 13, ausstehende Neustarts)
- Wartungsplaner: Updates und Wartungsarbeiten zeitgesteuert (z. B. nachts) ausführen –
  einmalig, täglich, wöchentlich, monatlich, mit Wartungsfenster, Neustart-Regel und E-Mail-Bericht
- Enrollment per Skript: neue Geräte fordern ihren WireGuard-Zugang selbst an; der Servermanager
  legt Peer, Routing und Adressliste auf dem MikroTik an und nimmt das Gerät in die Verwaltung auf
- Benutzerverwaltung mit Rollen und Rechten je System, Zwei-Faktor-Anmeldung, Audit-Log
- Backup/Restore des Servermanagers (optional verschlüsselt) und Konfigurations-Backups der Systeme
- Update des Servermanagers per Klick aus dem Git-Repository (mit automatischer Sicherung und Rollback)
- Installationsskript für Debian 13 (LXC)

---

## Inhalt

1. [Architektur](#architektur)
2. [Installation](#installation)
3. [Erste Schritte](#erste-schritte)
4. [WireGuard-Management-Netz mit MikroTik](#wireguard-management-netz-mit-mikrotik)
5. [Systeme hinzufügen](#systeme-hinzufügen)
6. [Funktionen je Systemtyp](#funktionen-je-systemtyp)
7. [Update-Übersicht und Wartungsplaner](#update-übersicht-und-wartungsplaner)
8. [Benutzer und Rechte](#benutzer-und-rechte)
9. [Backup und Restore](#backup-und-restore)
10. [Update des Servermanagers](#update-des-servermanagers)
11. [Kommandozeile](#kommandozeile)
12. [Sicherheit](#sicherheit)
13. [Dateien und Pfade](#dateien-und-pfade)
14. [Fehlerbehebung](#fehlerbehebung)
15. [Entwicklung](#entwicklung)

---

## Architektur

```
                        Internet
                           │ HTTPS (Weboberfläche, Enrollment-API)
                ┌──────────┴───────────┐
                │ Servermanager (LXC)  │  nginx → gunicorn (Flask) + Worker
                │ Debian 13            │  SQLite, SSH-Schlüssel, Jobs
                └──────────┬───────────┘
                           │ WireGuard wg-sm (z. B. 10.66.0.2)
                ┌──────────┴───────────┐
                │ MikroTik RouterOS 7  │  wg-mgmt 10.66.0.1/24, REST-API
                └───┬──────────┬───────┘  Peers, Routen, Adressliste
         WireGuard  │          │  WireGuard
            ┌───────┴──┐   ┌───┴────────┐          ┌──────────────┐
            │ Debian   │   │ Proxmox VE │          │ Bestands-    │
            │ 10.66.0.10│  │ 10.66.0.11 │          │ server       │◄── SSH direkt
            └──────────┘   └────────────┘          └──────────────┘
```

| Komponente | Aufgabe |
|---|---|
| `servermanager-web` | Weboberfläche und Enrollment-API (gunicorn hinter nginx) |
| `servermanager-worker` | führt Jobs aus, prüft regelmäßig Status/Updates, startet Wartungspläne, erstellt automatische Backups |
| `bin/sm-helper` | kleiner, streng prüfender Root-Helfer (per sudo) für WireGuard, Self-Update und Restore |
| Zielsysteme | werden per SSH (Schlüssel und/oder Passwort, optional sudo) verwaltet; auf den Zielen wird **kein Agent** installiert |

Langlaufende Paketoperationen (Upgrades, Release-Upgrade, ISPConfig-/Nextcloud-Update) laufen auf dem
Zielsystem **im Hintergrund** weiter. Bricht die SSH-/WireGuard-Verbindung ab oder wird der Worker neu
gestartet (z. B. beim Self-Update), verbindet sich der Servermanager wieder und liest das Protokoll
weiter.

---

## Installation

Voraussetzungen:

- Debian 13 (trixie), z. B. als LXC-Container auf Proxmox (1 vCPU, 1 GB RAM, 8 GB Speicher genügen für
  viele Systeme)
- öffentlich erreichbarer Name (für Let's Encrypt Port 80/443 erreichbar) – alternativ selbstsigniertes
  Zertifikat
- für das Management-Netz: MikroTik mit RouterOS 7 (REST-API über den Dienst `www-ssl`)

**WireGuard im LXC-Container:** Das Kernelmodul muss auf dem Proxmox-**Host** geladen sein:

```bash
# auf dem Proxmox-Host
modprobe wireguard
echo wireguard > /etc/modules-load.d/wireguard.conf
```

Danach funktioniert WireGuard auch in unprivilegierten Containern.

### Installationsskript

```bash
apt-get update && apt-get install -y git
git clone https://github.com/agrotevent/servermanager.git /root/servermanager
cd /root/servermanager
bash install.sh --domain sm.example.com --email admin@example.com
```

> Solange die Entwicklung noch nicht in `main` übernommen ist, den Branch angeben:
> `git clone -b <branch> …` und `bash install.sh --branch <branch> …`

Das Skript

1. installiert Python, git, WireGuard-Tools, nginx, certbot, sudo,
2. prüft, ob WireGuard-Interfaces angelegt werden können (mit Hinweis für LXC),
3. legt den Dienstbenutzer `servermanager` an und installiert den Code nach `/opt/servermanager`
   (Python-venv unter `/opt/servermanager/.venv`),
4. erzeugt Konfiguration, Hauptschlüssel, SSH-Schlüssel und Datenbank,
5. richtet sudo-Regel, systemd-Dienste und nginx mit Let's Encrypt (oder selbstsigniert) ein,
6. legt den ersten Administrator an und zeigt das Initialpasswort an.

Optionen (`bash install.sh --help`):

| Option | Bedeutung |
|---|---|
| `--domain FQDN` | öffentlicher Name |
| `--email ADRESSE` | für Let's Encrypt |
| `--tls letsencrypt\|selfsigned\|none` | Zertifikat; `none` = ohne nginx (eigener Reverse-Proxy) |
| `--repo URL`, `--branch NAME` | Quelle für Installation **und** spätere Updates |
| `--admin-user`, `--admin-password` | erster Administrator |
| `--listen 127.0.0.1:8000` | interne Adresse von gunicorn |
| `--timezone Europe/Berlin` | Zeitzone für Anzeige und Wartungsplaner |
| `--yes` | ohne Rückfragen |

Das Skript kann erneut ausgeführt werden (Reparatur/Aktualisierung); vorhandene Konfiguration,
Schlüssel und Daten bleiben erhalten.

Bei selbstsigniertem Zertifikat wird automatisch der **Zertifikats-Pin** hinterlegt – die
Enrollment-Befehle verwenden dann `curl --pinnedpubkey`, sodass auch ohne öffentliche CA eine sichere
Verbindung besteht.

---

## Erste Schritte

1. `https://<domain>` öffnen, mit dem angezeigten Initialpasswort anmelden und ein eigenes Passwort
   vergeben.
2. **Profil → Zwei-Faktor-Anmeldung** einrichten (unter *Einstellungen* für Administratoren erzwingbar).
3. **Einstellungen → Allgemein:** öffentliche URL prüfen (wird in die Enrollment-Befehle eingesetzt),
   Zeitzone.
4. Optional **Einstellungen → E-Mail** für Wartungsberichte.
5. **WireGuard** einrichten (nächster Abschnitt) – oder direkt Bestandsserver per SSH hinzufügen.

---

## WireGuard-Management-Netz mit MikroTik

Menü **WireGuard**:

1. Einstellungen ausfüllen: Management-Netz (z. B. `10.66.0.0/24`), Adresse des MikroTik (`10.66.0.1`),
   Adresse des Servermanagers (`10.66.0.2`), öffentlicher Endpoint (`vpn.example.com:13231`),
   API-URL (`https://10.66.0.1`), API-Benutzer/Passwort.
2. Die angezeigten **RouterOS-Befehle** im MikroTik-Terminal ausführen. Sie legen an:
   - WireGuard-Interface `wg-mgmt` mit Adresse,
   - den Peer des Servermanagers (sein Public Key ist bereits eingesetzt),
   - Firewall-Regeln: WireGuard erlauben, REST-API nur vom Servermanager, Servermanager → Clients
     erlauben, **Clients untereinander isolieren**,
   - Zertifikat und `www-ssl` für die REST-API,
   - einen API-Benutzer mit eingeschränkten Rechten, der sich nur aus dem Tunnel anmelden darf.

   Firewall-Regeln ggf. vor vorhandene `drop`-Regeln verschieben und das Passwort anpassen.
3. Public Key des MikroTik eintragen (`/interface wireguard print`) und speichern.
4. **Tunnel aktivieren** – der Servermanager schreibt `/etc/wireguard/wg-sm.conf` und startet
   `wg-quick@wg-sm`.
5. **API testen** – übernimmt Version, Identität und den Public Key automatisch.

Beim Enrollment eines Geräts legt der Servermanager über die REST-API an:

| Objekt | Inhalt |
|---|---|
| WireGuard-Peer | Public Key des Geräts, `allowed-address` = Geräte-IP/32 (+ geroutete Netze), Kommentar `servermanager:<id>:<name>` |
| Adressliste | Eintrag in `servermanager-clients` (für eigene Firewall-Regeln) |
| Routen | für optionale Netze hinter dem Gerät (z. B. VM-Netz eines Proxmox-Hosts), Gateway `wg-mgmt` |

Der eigene Tunnel des Servermanagers erhält automatisch Routen für das Management-Netz und alle
gerouteten Netze. Die Tabelle *Peers auf dem MikroTik* zeigt Handshakes und Traffic, erkennt fehlende
und verwaiste Peers und kann sie neu anlegen bzw. entfernen.

---

## Systeme hinzufügen

### Per Enrollment-Skript (empfohlen)

Menü **Enrollment** → Token erstellen (Einmal- oder Mehrfach-Token, Gültigkeit, Verbindungsart,
SSH-Benutzer, Systemtypen, geroutete Netze, Tags, Zugriffsrechte für Benutzer). Der angezeigte Befehl
wird auf dem neuen System als root ausgeführt:

```bash
curl -fsSL https://sm.example.com/enroll/<token>.sh | bash
# mit Optionen
curl -fsSL https://sm.example.com/enroll/<token>.sh | bash -s -- --name "Webserver 1"
```

| Option | Bedeutung |
|---|---|
| `--name NAME` | Anzeigename |
| `--direct` | ohne WireGuard, direkte SSH-Verbindung |
| `--address HOST` | Adresse für direkte Verbindungen – nur bei Tokens von Administratoren; sonst wird immer die Absenderadresse der Anfrage registriert |
| `--force` | vorhandene Tunnel-Konfiguration überschreiben |

Ablauf:

1. Das Skript installiert bei Bedarf `wireguard-tools`, erzeugt **lokal** ein WireGuard-Schlüsselpaar
   (der private Schlüssel verlässt das Gerät nie) und sendet Public Key, Hostname und die
   **SSH-Hostkeys** an den Servermanager.
2. Der Servermanager vergibt eine Management-IP, legt Peer/Route/Adressliste auf dem MikroTik an und
   antwortet mit der Tunnel-Konfiguration und seinem SSH-Public-Key.
3. Das Skript schreibt `/etc/wireguard/wg-mgmt.conf`, startet `wg-quick@wg-mgmt` und hinterlegt den
   SSH-Schlüssel – standardmäßig mit `from="<IP des Servermanagers>"`, der Schlüssel ist also nur aus dem
   Management-Netz nutzbar. Ist `PermitRootLogin no` gesetzt, wird automatisch der Benutzer `smadmin`
   mit sudo-Rechten verwendet.
4. Der Servermanager prüft die Verbindung (mit den übermittelten Hostkeys – kein „Trust on first use“),
   erkennt Docker, Nextcloud, ISPConfig und Proxmox und nimmt das System auf.

Proxmox-Hinweis: `/root/.ssh/authorized_keys` ist dort ein Link in das Cluster-Dateisystem – das Skript
schreibt in die Zieldatei und erhält den Link.

### Manuell per SSH (Bestandssysteme ohne Tunnel)

**Systeme → Manuell hinzufügen**: Host/IP, Port, Benutzer, Anmeldung per Servermanager-Schlüssel,
eigenem Schlüssel oder Passwort, sudo mit/ohne Passwort. Mit *SSH-Schlüssel automatisch installieren*
meldet sich der Servermanager einmal per Passwort an, hinterlegt seinen Schlüssel und stellt auf
Schlüssel-Anmeldung um. Der Hostkey wird beim ersten Verbindungsaufbau gespeichert und danach geprüft.

---

## Funktionen je Systemtyp

| Typ | Aktionen | Update-Erkennung |
|---|---|---|
| **Debian / Linux** (immer) | apt update, Updates installieren (upgrade bzw. dist-upgrade bei Proxmox), vollständiges Upgrade, nur Sicherheitsupdates, **Release-Upgrade 12 → 13** mit Vorprüfung, autoremove, Cache leeren, dpkg reparieren, Journal verkleinern, needrestart, Dienste starten/stoppen/neu starten, Neustart (mit Warten auf Rückkehr), Neustart falls erforderlich, beliebige Befehle | ausstehende Pakete inkl. Sicherheitsupdates, Neustart erforderlich (auch Kernel-Vergleich), fehlgeschlagene Units |
| **Nextcloud** | Status, Apps aktualisieren, Core-Update (updater.phar + occ upgrade + DB-Reparaturen), Wartungsmodus, DB-Indizes, Reparatur, Dateien neu einlesen, Cron | Core- und App-Updates (`occ update:check`), Wartungsmodus, DB-Upgrade nötig |
| **Docker** | Container starten/stoppen/neu starten/entfernen, Compose-Projekte aktualisieren (pull + up -d) oder neu starten, alle Projekte aktualisieren, ungenutzte Images entfernen | neue Images für laufende Container (optional, per `docker pull`) |
| **ISPConfig** | unbeaufsichtigtes Update (stable, mit ISPConfig-Backup, Dienste neu konfigurieren), Mail-Warteschlange abarbeiten | installierte vs. aktuelle Version, Dienste, Mail-Warteschlange, Fehler im cron.log |
| **Proxmox VE** | VMs/Container starten, herunterfahren, neu starten, Sicherung (vzdump), Upgrade-Prüfung (pve8to9) | Paketupdates (dist-upgrade), Cluster-Ressourcen, Storage |

Nextcloud in Docker oder als Snap: in den System-Einstellungen einen eigenen occ-Befehl hinterlegen
(z. B. `docker exec -u www-data nextcloud php occ`).

### Debian 12 → 13

Die Aktion *Release-Upgrade prüfen* führt nur die Vorprüfung aus (Architektur, Speicherplatz, dpkg-Status,
zurückgehaltene Pakete, Fremdquellen, ISPConfig-/Nextcloud-Hinweise). Das eigentliche Upgrade

1. sichert automatisch `/etc` (Konfig-Backup im Servermanager),
2. aktualisiert Debian 12 vollständig und sichert die APT-Quellen,
3. stellt `bookworm` → `trixie` um (Fremdquellen wahlweise mit umstellen oder deaktivieren),
4. bricht mit Rücksetzen der Quellen ab, falls `apt-get update` scheitert,
5. führt `upgrade --without-new-pkgs` und `full-upgrade` aus (bestehende Konfigurationsdateien bleiben
   erhalten, neue Paketversionen werden als `.dpkg-dist` gemeldet),
6. meldet den erforderlichen Neustart.

Proxmox-Hosts werden bewusst ausgeschlossen (eigener Upgrade-Weg über `pve8to9`).

---

## Update-Übersicht und Wartungsplaner

**Update-Übersicht** zeigt für alle sichtbaren Systeme: Anzahl Paketupdates und Sicherheitsupdates
(aufklappbar mit Paketliste), Anwendungs-Updates (Nextcloud, Docker, ISPConfig), verfügbares
Release-Upgrade, erforderlichen Neustart und den Zeitpunkt der letzten Prüfung. Filter: mit Updates,
Sicherheit, Neustart, Release-Upgrade, nicht aktuell geprüft. Mehrfachauswahl: erneut prüfen,
Sicherheitsupdates oder alle Updates sofort installieren, oder **„Für die Nacht planen …“**.

Die Prüfung läuft automatisch: alle 15 Minuten Status und Paketstand aus dem Cache, alle 6 Stunden
eine vollständige Prüfung mit `apt-get update` und Modul-Checks (Intervalle unter *Einstellungen*).

**Wartungsplaner** – ein Wartungsplan besteht aus

- **Zeitpunkt**: einmalig (Datum/Uhrzeit), täglich, wöchentlich (Wochentage) oder monatlich
  (Tag im Monat), in der eingestellten Zeitzone (Sommer-/Winterzeit wird berücksichtigt),
- **Zielen**: ausgewählte Systeme und/oder alle Systeme mit einem Tag (bei jeder Ausführung neu
  ausgewertet),
- **Aufgaben** in fester Reihenfolge: z. B. Updates installieren → Compose-Projekte aktualisieren →
  Nextcloud-Apps aktualisieren → eigener Befehl,
- **Optionen**: nur ausführen, wenn Updates anstehen; Konfig-Backup vorher; Abbruch bei Fehler;
  Neustart nie / falls erforderlich / immer (der Servermanager wartet, bis das System wieder da ist und
  prüft den Neustart anhand der Boot-ID),
- **Ausführung**: maximale Anzahl parallel gewarteter Systeme und Wartungsfenster (Systeme, die bis
  zum Ende des Fensters nicht gestartet wurden, werden übersprungen),
- **Bericht** per E-Mail (Administratoren werden bei Fehlern zusätzlich benachrichtigt).

Jeder Lauf erscheint mit allen Einzeljobs und Protokollen im Verlauf. Pläne können pausiert oder sofort
ausgeführt werden. Ausgeführt wird mit den Rechten des Erstellers – verliert er den Zugriff auf ein
System, wird es übersprungen.

---

## Benutzer und Rechte

| Rolle | Rechte |
|---|---|
| Administrator | alles: alle Systeme, Benutzer, Einstellungen, WireGuard, Backups, Update, Audit-Log |
| Manager | darf Systeme hinzufügen und Enrollment-Tokens erstellen; eigene neue Systeme erhält er mit Vollzugriff |
| Benutzer | nur zugewiesene Systeme |

Zuweisung je System (unter *Benutzer* oder im System unter *Zugriff*):

| Stufe | erlaubt |
|---|---|
| Lesen | Status, Updates, Protokolle ansehen |
| Bedienen | zusätzlich Updates installieren, Dienste/Container/VMs steuern, Neustart, Wartung planen, Konfig-Backups erstellen |
| Vollzugriff | zusätzlich beliebige Befehle, Release-Upgrade, Nextcloud-Core-Update, Zugangsdaten ändern, Backups herunterladen/wiederherstellen, System entfernen (Adresse, Hostkey und geroutete Netze bleiben Administratoren vorbehalten) |

Weitere Schutzmechanismen: Sperre nach 8 Fehlversuchen (15 Minuten), Drosselung je IP,
Sitzungsablauf, Invalidierung aller Sitzungen bei Passwortänderung, Audit-Log aller Aktionen.

---

## Backup und Restore

**Backup & Restore** (Administrator):

- Inhalt: Datenbank (konsistenter SQLite-Snapshot), Hauptschlüssel `secret.key`, Konfiguration,
  SSH-Schlüssel des Servermanagers, WireGuard-Konfiguration, optional die Konfig-Backups der Systeme.
- Optional verschlüsselt (scrypt + AES-256-GCM, manipulations- und kürzungssicher). Ohne Passphrase
  enthält die Datei den Hauptschlüssel und damit Zugriff auf alle gespeicherten Zugangsdaten – sicher
  aufbewahren!
- Automatisches tägliches Backup (Uhrzeit, Anzahl, Passphrase einstellbar) sowie automatisch vor jedem
  Update und vor jeder Wiederherstellung.
- Wiederherstellen per Upload oder aus der Liste: das Backup wird geprüft, der aktuelle Stand gesichert,
  die Dienste werden gestoppt, Daten eingespielt, migriert und neu gestartet.

Umzug/Notfall auf einen neuen Server:

```bash
bash install.sh --domain sm.example.com …     # neu installieren
servermanager-cli restore /root/servermanager-backup-….tar.gz.enc --passphrase '…' --yes
```

**Konfig-Backups der Systeme** (Tab *Konfig-Backups* im System): Archiv der konfigurierten Pfade
(Standard `/etc`) wird per SSH gezogen und im Servermanager gespeichert. Wiederherstellung wahlweise
in ein separates Verzeichnis auf dem System (`/root/servermanager-restore-…`, sicher) oder am
Originalort (Vollzugriff, mit Warnung).

---

## Update des Servermanagers

Menü **Update**: *Nach Updates suchen* zeigt die neuen Commits des konfigurierten Branches;
*Update installieren* erstellt eine Sicherung, holt den neuen Stand (`git reset --hard origin/<branch>`),
aktualisiert die Python-Abhängigkeiten, systemd-Units und die Datenbank und startet die Dienste neu.
Startet die Weboberfläche danach nicht, wird automatisch auf den vorherigen Stand zurückgesetzt.
Laufende Hintergrund-Jobs auf den Zielsystemen laufen weiter und werden danach wieder aufgenommen.

Private Repositories: bei der Installation `--repo https://<token>@github.com/…` angeben oder auf dem
Server einen Deploy-Key für root hinterlegen.

---

## Kommandozeile

```bash
servermanager-cli users                         # Benutzer auflisten
servermanager-cli create-admin NAME --generate  # Administrator anlegen
servermanager-cli reset-password NAME           # Passwort zurücksetzen
servermanager-cli disable-2fa NAME              # 2FA eines Benutzers deaktivieren
servermanager-cli get [SCHLÜSSEL]               # Einstellungen anzeigen
servermanager-cli set general.base_url https://sm.example.com
servermanager-cli backup [--passphrase …]
servermanager-cli restore DATEI [--passphrase …] [--yes]
servermanager-cli pubkey                        # SSH-Public-Key des Servermanagers
servermanager-cli migrate
```

Logs: `journalctl -u servermanager-web -u servermanager-worker -f`

---

## Sicherheit

- Passwörter mit Argon2id, TOTP-Zwei-Faktor-Anmeldung, CSRF-Schutz, strikte Content-Security-Policy,
  sichere Cookies, Login-Drosselung und Kontosperre.
- Zugangsdaten (Passwörter, private Schlüssel, API-Passwort, TOTP-Geheimnisse) verschlüsselt in der
  Datenbank; der Hauptschlüssel liegt getrennt in `/etc/servermanager/secret.key`.
- SSH-Hostkeys werden beim Enrollment sicher übertragen und bei jeder Verbindung geprüft – ein
  geänderter Hostkey blockiert die Verbindung.
- Der SSH-Schlüssel des Servermanagers wird auf den Zielen standardmäßig mit `from=` auf die
  Management-IP beschränkt; Clients im Management-Netz sind voneinander isoliert.
- Weil dieser Schlüssel auf allen Systemen hinterlegt ist, dürfen nur Administratoren Adressen/Ports
  ändern, Hostkeys zurücksetzen, geroutete Netze setzen und Systeme ohne Passwortnachweis mit dem
  Schlüssel anlegen. Manager legen manuelle Systeme per Passwort (oder eigenem Schlüssel) an; der
  Schlüssel wird dann nach erfolgreicher Passwort-Anmeldung installiert. Beim Enrollment ohne Tunnel
  wird die tatsächliche Absenderadresse registriert.
- Skripte, die per sudo als root laufen, werden vor der Ausführung in den Speicher bzw. in ein
  root-eigenes Verzeichnis übernommen und können vom Anmeldebenutzer nicht mehr verändert werden.
- Die Weboberfläche läuft als unprivilegierter Benutzer; nur `bin/sm-helper` darf per sudo als root
  laufen und prüft alle Eingaben (u. a. werden WireGuard-Konfigurationen mit Hooks wie `PostUp`
  abgelehnt).
- Parameter von Aktionen werden serverseitig gegen Muster geprüft und als Umgebungsvariablen (nie per
  String-Verkettung) an die Skripte übergeben.
- Enrollment-Tokens sind zufällig, nur gehasht gespeichert, zeitlich begrenzt und auf eine Anzahl
  Verwendungen beschränkt.

---

## Dateien und Pfade

| Pfad | Inhalt |
|---|---|
| `/opt/servermanager` | Programmcode (Git-Checkout, root-eigen), `.venv` |
| `/etc/servermanager/servermanager.conf` | Grundkonfiguration (Pfade, URL, Branch) |
| `/etc/servermanager/secret.key` | Hauptschlüssel |
| `/etc/servermanager/tls/` | selbstsigniertes Zertifikat |
| `/var/lib/servermanager/servermanager.db` | Datenbank |
| `/var/lib/servermanager/ssh/` | SSH-Schlüsselpaar des Servermanagers |
| `/var/lib/servermanager/jobs/` | Job-Protokolle |
| `/var/lib/servermanager/backups/` | Backups des Servermanagers |
| `/var/lib/servermanager/system-backups/` | Konfig-Backups der Systeme |
| `/var/log/servermanager/` | Protokolle von Self-Update und Wiederherstellung |
| `/var/backups/servermanager-pre-restore-*` | Stand vor einer Wiederherstellung (Datenbank, Schlüssel) |
| `/var/lib/servermanager-jobs/` (auf Zielsystemen) | Protokolle von Hintergrund-Jobs während der Ausführung |

---

## Fehlerbehebung

| Problem | Lösung |
|---|---|
| „WireGuard-Interfaces können nicht angelegt werden“ im LXC | `modprobe wireguard` auf dem Proxmox-Host (siehe oben) |
| Dashboard meldet, der Worker antworte nicht | `systemctl status servermanager-worker`, `journalctl -u servermanager-worker` |
| Enrollment: „Servermanager nicht erreichbar“ | öffentliche URL unter *Einstellungen*, Firewall/Port 443, bei selbstsigniertem Zertifikat den Pin (Einstellungen → Enrollment) prüfen |
| Kein WireGuard-Handshake auf dem Client | Endpoint (UDP-Port) erreichbar? Firewall-Regel auf dem MikroTik vor `drop`-Regeln? |
| „Hostkey hat sich geändert“ | nach Neuinstallation eines Systems: System → Verwaltung → Hostkey zurücksetzen (sonst Angriff prüfen!) oder erneut per Enrollment-Token mit „Erneutes Enrollment“ |
| MikroTik-API: 401 | Benutzer, Passwort, `address=`-Einschränkung und Gruppe (`rest-api`, `read`, `write`) prüfen |
| Passwort vergessen | `servermanager-cli reset-password NAME` |

---

## Entwicklung

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
# ohne /etc/servermanager/servermanager.conf wird ./dev-data verwendet
python -m servermanager.cli create-admin admin --password 'Dev-Passwort-123'
flask --app servermanager.web.wsgi run --debug        # Weboberfläche
python -m servermanager.worker                        # Worker (zweites Terminal)
pytest                                                # Tests
```

Aufbau des Codes:

| Pfad | Inhalt |
|---|---|
| `servermanager/models.py` | Datenmodell (SQLAlchemy) |
| `servermanager/ssh.py` | SSH-Schicht (paramiko): Hostkey-Prüfung, sudo, Streaming, Hintergrund-Jobs |
| `servermanager/modules/` | Systemtypen mit Aktionen, Panels und Update-Erkennung; `scripts/` enthält die Shell-Skripte |
| `servermanager/worker.py` | Job-Ausführung, periodische Prüfungen, Wartungsplaner |
| `servermanager/schedules.py` | Berechnung der Termine, Anlegen der Wartungsläufe |
| `servermanager/wireguard.py`, `mikrotik.py` | Management-Netz und RouterOS-REST-API |
| `servermanager/enrollment.py` | Tokens und Enrollment-API, Client-Skript unter `web/templates/enroll/` |
| `servermanager/backup.py`, `sysbackup.py` | Backups des Servermanagers bzw. der Systeme |
| `servermanager/web/` | Flask-Oberfläche (Blueprints, Templates, CSS/JS ohne externe Abhängigkeiten) |
| `bin/` | Root-Helfer, Self-Update, CLI-Wrapper |
| `deploy/` | systemd-Units, nginx-Vorlage, Beispielkonfiguration |
