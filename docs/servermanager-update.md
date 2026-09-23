# Update des Servermanagers

Menü **Update**: *Nach Updates suchen* zeigt die neuen Commits des konfigurierten Branches;
*Update installieren* erstellt eine Sicherung, holt den neuen Stand (`git reset --hard origin/<branch>`),
aktualisiert die Python-Abhängigkeiten, systemd-Units und die Datenbank und startet die Dienste neu.
Startet die Weboberfläche danach nicht, wird automatisch auf den vorherigen Stand zurückgesetzt.
Laufende Hintergrund-Jobs auf den Zielsystemen laufen weiter und werden danach wieder aufgenommen.

Private Repositories: bei der Installation `--repo https://<token>@github.com/…` angeben oder auf dem
Server einen Deploy-Key für root hinterlegen.
