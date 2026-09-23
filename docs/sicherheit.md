# Sicherheit

- Passwörter mit Argon2id, TOTP-Zwei-Faktor-Anmeldung, CSRF-Schutz, strikte Content-Security-Policy,
  sichere Cookies, Login-Drosselung und Kontosperre.
- Zugangsdaten (Passwörter, private Schlüssel, API-Passwort, TOTP-Geheimnisse) verschlüsselt in der
  Datenbank; der Hauptschlüssel liegt getrennt in `/etc/servermanager/secret.key`.
- SSH-Hostkeys werden beim Enrollment sicher übertragen und bei jeder Verbindung geprüft – ein
  geänderter Hostkey blockiert die Verbindung.
- Der SSH-Schlüssel des Servermanagers wird auf den Zielen standardmäßig mit `from=` auf die
  Management-IP beschränkt; Clients im Management-Netz sind voneinander isoliert.
- Weil dieser Schlüssel auf allen Systemen hinterlegt ist, dürfen nur Administratoren Adressen/Ports
  ändern, Hostkeys zurücksetzen, geroutete Netze setzen und Systeme ohne Passwortnachweis mit dem
  Schlüssel anlegen. Manager legen manuelle Systeme per Passwort (oder eigenem Schlüssel) an; der
  Schlüssel wird dann nach erfolgreicher Passwort-Anmeldung installiert. Beim Enrollment ohne Tunnel
  wird die tatsächliche Absenderadresse registriert.
- Skripte, die per sudo als root laufen, werden vor der Ausführung in den Speicher bzw. in ein
  root-eigenes Verzeichnis übernommen und können vom Anmeldebenutzer nicht mehr verändert werden.
- Die Weboberfläche läuft als unprivilegierter Benutzer; nur `bin/sm-helper` darf per sudo als root
  laufen und prüft alle Eingaben (u. a. werden WireGuard-Konfigurationen mit Hooks wie `PostUp`
  abgelehnt).
- Parameter von Aktionen werden serverseitig gegen Muster geprüft und als Umgebungsvariablen (nie per
  String-Verkettung) an die Skripte übergeben.
- Das Repository-Token (privates Repository) liegt nur für root lesbar in
  `/etc/servermanager/git-credentials`, wird an `sm-helper` ausschließlich über stdin übergeben und nie
  angezeigt (nur die letzten vier Zeichen). Es sollte nur Leserechte auf dieses eine Repository haben.
- Enrollment-Tokens sind zufällig, nur gehasht gespeichert, zeitlich begrenzt und auf eine Anzahl
  Verwendungen beschränkt.
