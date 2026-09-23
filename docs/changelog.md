# Änderungsprotokoll

Alle wesentlichen Änderungen am Servermanager. Neue Einträge stehen oben.

## 1.0.0 – 23.09.2026

Erste Version.

### Neu

- Verwaltung von Debian 12/13, Nextcloud, Docker, ISPConfig und Proxmox VE über SSH (Schlüssel
  und/oder Passwort, sudo mit oder ohne Passwort, Hostkey-Prüfung).
- WireGuard-Management-Netz auf MikroTik (RouterOS 7): eigener Tunnel des Servermanagers,
  RouterOS-Einrichtungsbefehle, Peer-Übersicht.
- Enrollment per Skript: Geräte fordern ihren WireGuard-Zugang an, Peer/Route/Adressliste werden über
  die REST-API angelegt, SSH-Schlüssel und Hostkeys werden sicher übernommen.
- Direkte SSH-Verwaltung bestehender Systeme ohne Tunnel.
- Update-Übersicht über alle Geräte (Pakete, Sicherheitsupdates, Anwendungs-Updates,
  Release-Upgrade, Neustart).
- Wartungsplaner für zeitgesteuerte Updates und Wartungsarbeiten (einmalig, täglich, wöchentlich,
  monatlich; Wartungsfenster, Neustart-Regel, E-Mail-Bericht).
- Release-Upgrade Debian 12 → 13 mit Vorprüfung, Sicherung und automatischem Zurücksetzen der Quellen.
- Hintergrund-Jobs überstehen Verbindungsabbrüche und Neustarts des Servermanagers.
- Benutzer mit Rollen und Rechten je System, Zwei-Faktor-Anmeldung, Audit-Log.
- Backup/Restore des Servermanagers (optional verschlüsselt), Konfigurations-Backups der Systeme.
- Update des Servermanagers per Klick aus dem Git-Repository mit Rollback.
- Installationsskript für Debian 13 (LXC), nginx mit Let's Encrypt oder selbstsigniertem Zertifikat.
- Hilfe in der Weboberfläche.

### Sicherheit

- Adressen, Hostkeys und geroutete Netze können nur Administratoren ändern; Manager müssen beim
  Anlegen von Systemen einen Zugang nachweisen.
- Der Root-Helfer arbeitet nicht in Verzeichnissen des Dienstbenutzers und lehnt WireGuard-Hooks ab.
