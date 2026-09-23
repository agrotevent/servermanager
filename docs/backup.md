# Backup und Restore

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
