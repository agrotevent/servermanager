# Änderungsprotokoll

Alle wesentlichen Änderungen am Servermanager. Neue Einträge stehen oben.

## 1.2.0 – 26.09.2026

### Neu

- **Proxmox VE über die API:** mehrere Server/Cluster mit API-Token (auch automatisch per SSH
  eingerichtet) und Zertifikats-Pinning; Container und VMs starten, herunterfahren, neu starten,
  stoppen, Snapshots, Sicherungen (vzdump), Ressourcen ändern, Disk vergrößern, löschen; Verlauf von
  CPU/RAM/Netz/Disk als Diagramme; Überwachung mit Warnungen (Node offline, Quorum, überwachter Gast
  läuft nicht, Disk/Storage voll).
- **Container anlegen** mit Vorlagen-Download, DHCP oder statischer IP, SSH-Schlüssel des
  Servermanagers; optional direkt als System aufnehmen, DHCP-Lease auf dem RouterOS statisch machen und
  über Pangolin veröffentlichen.
- Systeme lassen sich einem Proxmox-Gast zuordnen: Start/Stopp auf der System-Seite mit den Rechten des
  Systems.
- **RouterOS über die API** (mehrere Router, z. B. CHR): Übersicht, DHCP/Leases (statisch machen),
  NAT/Portweiterleitungen, Routing & Mangle, Firewall-Anzeige, DNS, Ping-Test.
- **Konfigurationsanalyse** für bestehende Router: Import per API oder `/export`, Soll-Ist-Vergleich
  (WAN, LAN/DHCP, DNS, NAT, Policy-Routing mit Mangle, FastTrack, MSS-Clamping, Firewall, Dienste),
  Anwenden unkritischer Änderungen mit vorheriger Sicherung, Skript für den Rest.
- **Pangolin:** Dienste mit Domain und Ziel (IP:Port) veröffentlichen, Ziele und Anmeldung verwalten,
  Überwachung der Newt-Sites.
- Rechte je API-Verbindung (Lesen/Bedienen/Vollzugriff) in der Benutzerverwaltung, Warnungen auf dem
  Dashboard und per E-Mail, neue Hilfeseiten.

### Geändert

- Datenbank-Schema Version 2 (wird beim Update automatisch migriert).

## 1.1.0 – 23.09.2026

### Neu

- Installation und Updates aus einem **privaten Repository** mit Lese-Token: `install.sh --token`
  (oder `SM_GIT_TOKEN`, bzw. verdeckte Abfrage), Ablage root-only in
  `/etc/servermanager/git-credentials`, automatische Verwendung durch `sm-update` und die
  Update-Prüfung.
- Menü **Update**: Token-Status anzeigen, neues Token prüfen und hinterlegen oder entfernen.

### Geändert

- Ein in der Repository-Adresse enthaltenes Token wird bei erneuter Installation in den
  Credential-Speicher verschoben.

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
