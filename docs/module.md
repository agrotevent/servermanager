# Funktionen je Systemtyp

| Typ | Aktionen | Update-Erkennung |
|---|---|---|
| **Debian / Linux** (immer) | apt update, Updates installieren (upgrade bzw. dist-upgrade bei Proxmox), vollständiges Upgrade, nur Sicherheitsupdates, **Release-Upgrade 12 → 13** mit Vorprüfung, autoremove, Cache leeren, dpkg reparieren, Journal verkleinern, needrestart, Dienste starten/stoppen/neu starten, Neustart (mit Warten auf Rückkehr), Neustart falls erforderlich, beliebige Befehle | ausstehende Pakete inkl. Sicherheitsupdates, Neustart erforderlich (auch Kernel-Vergleich), fehlgeschlagene Units |
| **Nextcloud** | Status, Apps aktualisieren, Core-Update (updater.phar + occ upgrade + DB-Reparaturen), Wartungsmodus, DB-Indizes, Reparatur, Dateien neu einlesen, Cron | Core- und App-Updates (`occ update:check`), Wartungsmodus, DB-Upgrade nötig |
| **Docker** | Container starten/stoppen/neu starten/entfernen, Compose-Projekte aktualisieren (pull + up -d) oder neu starten, alle Projekte aktualisieren, ungenutzte Images entfernen | neue Images für laufende Container (optional, per `docker pull`) |
| **ISPConfig** | unbeaufsichtigtes Update (stable, mit ISPConfig-Backup, Dienste neu konfigurieren), Mail-Warteschlange abarbeiten | installierte vs. aktuelle Version, Dienste, Mail-Warteschlange, Fehler im cron.log |
| **Mailcow** | Update prüfen (`update.sh --check`), **Mailcow aktualisieren** (`update.sh --force`, optional vorher sichern und ohne Ping-Prüfung), Sicherung (`helper-scripts/backup_and_restore.sh backup all`) | neuer Stand auf GitHub (`update.sh --check`), Container-Status |
| **CloudPanel** | CloudPanel aktualisieren (`clp-update`), Cloudflare-IPs aktualisieren; Sites, Datenbanken, Benutzer und Let's Encrypt unter *Infrastruktur → CloudPanel* ([CloudPanel](cloudpanel.md)) | installierte Version (`dpkg`), Zertifikatslaufzeiten |
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

### Nextcloud: Benutzer

Im Nextcloud-Reiter eines Systems führt **Benutzer verwalten** zur Benutzerverwaltung über `occ`
(anlegen, sperren, neues Passwort, löschen) – siehe [Nextcloud, Mailcow & SSO](apps.md).

### Newt (Pangolin-Tunnel)

Wird erkannt, wenn Newt als Programm (`/usr/local/bin/newt`, systemd-Dienst `newt`) oder als
Docker-Container `fosrl/newt` läuft.

- **Anzeige:** Betriebsart, Status, Version, Pangolin-Endpoint, letzte Meldungen (Secrets werden
  ausgeblendet).
- **Aktionen:** *Newt neu starten* (Bedienen), *Newt aktualisieren* (Vollzugriff; lädt die neueste
  Version von GitHub, nur bei der vom Servermanager eingerichteten systemd-Installation).
- Einrichtung und Zuordnung zu einem Pangolin-Server: siehe [Pangolin](pangolin.md).

### Asterisk/FreePBX

Wird erkannt, wenn `asterisk` installiert ist; FreePBX zusätzlich an `fwconsole`.

- **Anzeige:** Status, Laufzeit, Versionen (Asterisk, FreePBX), aktive Gespräche, Trunk-Registrierungen,
  angemeldete Nebenstellen.
- **Aktionen:** *Konfiguration neu laden* (Bedienen), *FreePBX-Module aktualisieren* und *Asterisk neu
  starten* (Vollzugriff; trennt laufende Gespräche). Alle drei sind im Wartungsplaner verwendbar.
- **Update-Prüfung:** verfügbare FreePBX-Modul-Updates (`fwconsole ma showupgrades`) erscheinen in der
  Update-Übersicht. Asterisk-Pakete des Betriebssystems laufen über die normalen Debian-Updates.
- Überwachung, Nebenstellen und SIP-Erreichbarkeit: siehe [Telefonie](telefonie.md).

### ISPConfig: Schnittstelle

Wird ein System als ISPConfig erkannt, richtet der Servermanager automatisch die Remote-API ein und
legt die Verbindung unter *Infrastruktur → ISPConfig* an – siehe [ISPConfig](ispconfig.md).

### Mailcow: Update

Erkannt wird mailcow-dockerized unter `/opt/mailcow-dockerized` (sonst `/root/…` oder `/srv/…`) an
`mailcow.conf` und `update.sh`. Bei bestehenden Systemen einmal *Update-Prüfung* mit Typerkennung
ausführen, z. B. über *Auf dem System erkennen* auf der Seite der Mailcow-Verbindung. Diese Verbindung
zeigt den Stand und verlinkt auf die Aktionen, wenn unter *Bearbeiten* das System (SSH) verknüpft ist.

- **Mailcow aktualisieren** (Vollzugriff) führt das offizielle `update.sh --force` aus, ohne Rückfragen.
  Neuer Code und neue Images werden geladen, die Container neu gestartet. Mail und Webmail sind dabei
  einige Minuten weg.
  - Holt sich `update.sh` zuerst neue Module und verlangt einen Neustart (Exit-Code 2), startet der
    Servermanager es ein zweites Mal.
  - Der Job läuft vom SSH-Abbruch unabhängig weiter. Am Ende stehen Version und nicht laufende
    Container im Protokoll.
- **Vorher sichern** ruft vor dem Update `backup_and_restore.sh backup all` auf (Ordner wählbar,
  Vorgabe `/var/backups/mailcow`). Scheitert die Sicherung, startet das Update nicht.
- **Internet-Prüfung per Ping überspringen** (`--skip-ping-check`), wenn ICMP nach außen gesperrt ist.
- Nach dem Update wird sofort neu geprüft, die Update-Übersicht ist damit aktuell. Regelmäßig geprüft
  wird bei jeder tiefen Prüfung. Das Update lässt sich im **Wartungsplaner** einplanen, z. B. nachts.

