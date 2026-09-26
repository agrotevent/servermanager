# Überblick

Webbasiertes Werkzeug zur Verwaltung und Wartung von Linux-Servern – **Debian 12/13, Nextcloud,
Docker, ISPConfig und Proxmox VE** – über SSH, wahlweise durch ein **WireGuard-Management-Netz auf
einem MikroTik (RouterOS 7)** oder direkt per SSH für bestehende Systeme ohne Tunnel.

- Update-Übersicht: welches Gerät hat welche Aktualisierungen offen (Pakete, Sicherheitsupdates,
  Nextcloud-Core/Apps, Docker-Images, ISPConfig, Release-Upgrade 12 → 13, ausstehende Neustarts)
- Wartungsplaner: Updates und Wartungsarbeiten zeitgesteuert (z. B. nachts) ausführen –
  einmalig, täglich, wöchentlich, monatlich, mit Wartungsfenster, Neustart-Regel und E-Mail-Bericht
- Enrollment per Skript: neue Geräte fordern ihren WireGuard-Zugang selbst an; der Servermanager
  legt Peer, Routing und Adressliste auf dem MikroTik an und nimmt das Gerät in die Verwaltung auf
- **Proxmox VE über die API** (ein oder mehrere Server/Cluster): Container und VMs steuern, überwachen
  (Verlauf, Warnungen) und Container anlegen – auf Wunsch direkt als System verwaltet, mit fixierter
  DHCP-Lease und über Pangolin veröffentlicht
- **RouterOS über die API** (z. B. CHR mit öffentlicher IP): DHCP/Leases, NAT, Routing, DNS und eine
  Konfigurationsanalyse für bestehende Router (NAT/Mangle/Policy-Routing, Firewall, Dienste)
- **Pangolin**: Dienste aus dem internen Netz per Domain und Ziel-IP:Port veröffentlichen, Newt-Sites
  überwachen – mit zweitem Pangolin-Server als Backup-Weg und Tunnel-Containern auf verschiedenen Hosts
- **Nextcloud, Mailcow & SSO**: Benutzer und Postfächer verwalten, Nextcloud und Mailcow per Klick an
  authentik anbinden; Mailcow mit eigener Public-IP für IMAP/SMTP
- **Bestand übernehmen & Optimierungen**: vorhandene Geräte einlesen, Management-Zugänge anlegen,
  Verbesserungen vorschlagen und nach Bestätigung umsetzen – Ziel: nur eine Public-IP
- Benutzerverwaltung mit Rollen und Rechten je System, Zwei-Faktor-Anmeldung, Audit-Log
- Backup/Restore des Servermanagers (optional verschlüsselt) und Konfigurations-Backups der Systeme
- Update des Servermanagers per Klick aus dem Git-Repository (mit automatischer Sicherung und Rollback)
- Installationsskript für Debian 13 (LXC)

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
| API-Verbindungen | Proxmox-API (Port 8006), RouterOS-REST (`www-ssl`), Pangolin-Integration-API – vom Web-Prozess und Worker abgefragt |
| `bin/sm-helper` | kleiner, streng prüfender Root-Helfer (per sudo) für WireGuard, Self-Update und Restore |
| Zielsysteme | werden per SSH (Schlüssel und/oder Passwort, optional sudo) verwaltet; auf den Zielen wird **kein Agent** installiert |

Langlaufende Paketoperationen (Upgrades, Release-Upgrade, ISPConfig-/Nextcloud-Update) laufen auf dem
Zielsystem **im Hintergrund** weiter. Bricht die SSH-/WireGuard-Verbindung ab oder wird der Worker neu
gestartet (z. B. beim Self-Update), verbindet sich der Servermanager wieder und liest das Protokoll
weiter.
