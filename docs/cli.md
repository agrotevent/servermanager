# Kommandozeile

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
