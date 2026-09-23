# Update des Servermanagers

Menü **Update**: *Nach Updates suchen* zeigt die neuen Commits des konfigurierten Branches;
*Update installieren* erstellt eine Sicherung, holt den neuen Stand (`git reset --hard origin/<branch>`),
aktualisiert die Python-Abhängigkeiten, systemd-Units und die Datenbank und startet die Dienste neu.
Startet die Weboberfläche danach nicht, wird automatisch auf den vorherigen Stand zurückgesetzt.
Laufende Hintergrund-Jobs auf den Zielsystemen laufen weiter und werden danach wieder aufgenommen.

## Privates Repository / Zugriffstoken

Bei einem privaten Repository verwenden Update-Prüfung und Update das bei der Installation mit
`--token` hinterlegte Lese-Token (`/etc/servermanager/git-credentials`, nur root lesbar; siehe
[Installation](installation.md)).

Im Menü **Update** zeigt der Bereich *Zugriff auf das Repository*, ob ein Token hinterlegt ist
(Host, Benutzer und die letzten vier Zeichen). Dort kann ein Administrator

- ein **neues Token hinterlegen** – es wird vor dem Speichern gegen das Repository geprüft
  (`git ls-remote`); ein ungültiges Token ersetzt das bisherige nicht,
- das **Token entfernen** (nur sinnvoll bei einem öffentlichen Repository).

Beide Aktionen werden im Audit-Log protokolliert (`update.token_set`, `update.token_remove`).
Läuft ein Token ab, schlägt *Nach Updates suchen* mit einem Authentifizierungsfehler fehl – dann
einfach ein neues Token hinterlegen.

Auf der Kommandozeile (als root): `bash /opt/servermanager/install.sh --token NEUES_TOKEN` oder
`echo NEUES_TOKEN | /opt/servermanager/bin/sm-helper set-git-token`.
