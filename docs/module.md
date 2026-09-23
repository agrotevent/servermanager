# Funktionen je Systemtyp

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
