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
- Proxmox VE über die API: Container/VMs steuern, überwachen und anlegen (inkl. statischer DHCP-Lease
  und Veröffentlichung über Pangolin)
- RouterOS (z. B. CHR) über die API: DHCP, NAT, Routing/Mangle, DNS und Konfigurationsanalyse
  bestehender Router
- Pangolin: Dienste aus dem internen Netz unter einer Domain veröffentlichen
- Benutzerverwaltung mit Rollen und Rechten je System, Zwei-Faktor-Anmeldung, Audit-Log
- Backup/Restore des Servermanagers (optional verschlüsselt) und Konfigurations-Backups der Systeme
- Update des Servermanagers per Klick aus dem Git-Repository (mit automatischer Sicherung und Rollback)
- Installationsskript für Debian 13 (LXC)

## Schnellstart

Auf einem Debian-13-System (z. B. LXC-Container) als root:

```bash
apt-get update && apt-get install -y git
git clone https://github.com/agrotevent/servermanager.git /root/servermanager
cd /root/servermanager
bash install.sh --domain sm.example.com --email admin@example.com
```

> Solange die Entwicklung noch nicht in `main` übernommen ist, den Branch angeben:
> `git clone -b <branch> …` und `bash install.sh --branch <branch> …`

**Privates Repository** – mit einem Lese-Token (GitHub: Fine-grained Token, *Contents: Read-only*);
das Token wird für spätere Updates root-only hinterlegt:

```bash
TOKEN=github_pat_xxxxxxxx
apt-get update && apt-get install -y git curl
curl -fsSL -H "Authorization: Bearer $TOKEN" \
  https://raw.githubusercontent.com/agrotevent/servermanager/main/install.sh -o install.sh
bash install.sh --token "$TOKEN" --domain sm.example.com --email admin@example.com
```

Details: [Installation aus einem privaten Repository](docs/installation.md#installation-aus-einem-privaten-repository-token).

Danach die angezeigte Adresse öffnen und mit dem ausgegebenen Initialpasswort anmelden.

## Dokumentation

Die vollständige Dokumentation liegt im Verzeichnis [`docs/`](docs/) und ist in der Weboberfläche unter
**Hilfe** erreichbar (mit Suche und kontextbezogenen Hilfe-Links auf jeder Seite). Sie wird zusammen mit
dem Code gepflegt und mit jedem Update des Servermanagers aktualisiert.

- [Überblick & Architektur](docs/index.md)
- [Installation](docs/installation.md)
- [Erste Schritte](docs/erste-schritte.md)
- [Bedienung der Oberfläche](docs/oberflaeche.md)
- [Systeme hinzufügen](docs/systeme.md)
- [Funktionen je Systemtyp](docs/module.md)
- [Update-Übersicht & Wartungsplaner](docs/updates-wartung.md)
- [WireGuard & MikroTik](docs/wireguard.md)
- [Benutzer und Rechte](docs/benutzer.md)
- [Proxmox VE über die API](docs/proxmox.md)
- [RouterOS (CHR) über die API](docs/routeros.md)
- [Pangolin: Dienste veröffentlichen](docs/pangolin.md)
- [Backup und Restore](docs/backup.md)
- [Update des Servermanagers](docs/servermanager-update.md)
- [Kommandozeile](docs/cli.md)
- [Sicherheit](docs/sicherheit.md)
- [Dateien und Pfade](docs/dateien.md)
- [Fehlerbehebung](docs/fehlerbehebung.md)
- [Entwicklung & Pflege der Dokumentation](docs/entwicklung.md)
- [Änderungsprotokoll](docs/changelog.md)
