# Entwicklung

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

### Dokumentation pflegen

Diese Hilfe besteht aus den Markdown-Dateien im Verzeichnis `docs/` und wird unter **Hilfe** in der
Weboberfläche angezeigt. Sie wird zusammen mit dem Code gepflegt:

1. Bei jeder Änderung an Funktionen die betroffene Seite in `docs/` anpassen.
2. Im [Änderungsprotokoll](changelog.md) unter der aktuellen Version einen Eintrag ergänzen; bei einer
   neuen Version die Versionsnummer in `servermanager/__init__.py` erhöhen und einen neuen Abschnitt
   `## <Version> – <Datum>` anlegen.
3. Neue Seiten in der Seitenliste `PAGES` in `servermanager/web/views/help.py` eintragen.

Der Test `tests/test_help.py` prüft, dass alle Seiten vorhanden sind, interne Links funktionieren und
das Änderungsprotokoll einen Eintrag für die aktuelle Version enthält.
