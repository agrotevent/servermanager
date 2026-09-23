# Dateien und Pfade

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
