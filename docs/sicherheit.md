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
- API-Verbindungen zu Proxmox, RouterOS und Pangolin: Tokens/Passwörter verschlüsselt in der Datenbank;
  selbstsignierte Zertifikate werden per SHA-256-Fingerabdruck gepinnt statt die Prüfung abzuschalten;
  Anfragen gehen nie über einen Proxy aus der Umgebung. Empfohlen: eigene API-Benutzer mit minimalen
  Rechten und Zugriff nur aus dem Management-Netz.
- Die RouterOS-Analyse ändert Firewall, IP-Dienste und Benutzer nie selbst (nur Skriptvorschlag), legt
  vor Änderungen eine Sicherung auf dem Router an und protokolliert jede Änderung im Audit-Log.
- Nur Administratoren können Systeme mit Proxmox-Gästen verknüpfen (die Verknüpfung erlaubt
  Start/Stopp über die Systemrechte).
- Anmeldung per SSO (authentik): OpenID Connect mit PKCE, State und Nonce; Code-Einlösung nur über die
  gepinnte interne Adresse; Administratoren nur nach ausdrücklicher Freigabe; eine lokale
  Zwei-Faktor-Anmeldung gilt weiter; fehlgeschlagene SSO-Anmeldungen zählen zur Login-Drosselung und
  stehen im Audit-Log.
- easybell (AMI ohne TLS): Anmeldung nur per MD5-Challenge (Klartext-Passwort nur nach ausdrücklicher
  Freigabe), Werte mit Zeilenumbrüchen werden abgelehnt (keine eingeschleusten AMI-Befehle), das
  Anrufjournal wird nach der eingestellten Frist gelöscht.
- Enrollment-Tokens sind zufällig, nur gehasht gespeichert, zeitlich begrenzt und auf eine Anzahl
  Verwendungen beschränkt.

## Sicherheitsprüfung (Version 1.11.1)

Der gesamte Code wurde auf Sicherheitslücken geprüft. Behoben wurden:

| Schwere | Lücke | Behebung |
|---|---|---|
| hoch | Konfigurations-Backup: Pfade wie `/--remove-files` wurden von `tar` (als root) als Option gelesen | Pfadteile mit `-` werden abgelehnt, `--` vor der Pfadliste |
| hoch | Bestand übernehmen: eingetippte oder vom Gast gemeldete Adresse konnte ein fremdes System übernehmen (Hostkeys überschrieben, neues System mit dem Servermanager-Schlüssel auf beliebige Adresse) | Adresse von Hand nur für Administratoren; Adresse eines anderen Systems wird abgelehnt; ohne Hostkeys kein Zugang |
| hoch | `sm-helper restore-apply`: Dateioperationen als root in einem Verzeichnis des Dienstbenutzers (Symlink-Wettlauf → root) | alles unter dem Datenverzeichnis läuft als Dienstbenutzer, `secret.key` über ein privates root-Verzeichnis; nicht mehr direkt per sudo aufrufbar |
| hoch | „Bedienen“ genügte für neue Passwörter (u. a. authentik-Administratoren → Übernahme aller SSO-Anwendungen) | neue Passwörter/SIP-Kennwörter nur mit Vollzugriff; authentik-Admin-Konten nur durch Administratoren |
| mittel | WireGuard-MikroTik: Anmeldung über TLS ohne Zertifikatsprüfung | Fingerabdruck-Pinning oder CA-Prüfung Pflicht, kein http |
| mittel | Container anlegen nutzte verknüpften Pangolin/RouterOS ohne Rechteprüfung | Rechte auf Pangolin (Vollzugriff) und Router (Bedienen) werden geprüft |
| mittel | Webhooks/Enrollment: bis zu 2 GB große Anfragen ohne Anmeldung | 1 MB für alle Endpunkte ohne Sitzung (App und nginx) |
| mittel | Open Redirect nach der Anmeldung (`next=/%09/…`) | strenge Prüfung lokaler Ziele |
| mittel | PID-Datei der Skripte in `/tmp`: lokaler Benutzer auf dem Zielsystem konnte beeinflussen, was beim Abbruch beendet wird | Skript und PID-Datei in privatem Verzeichnis, nur gültige Prozessnummern |
| niedrig | Einmal-Enrollment-Token durch parallele Anfragen mehrfach nutzbar | Verwendung wird atomar vor der Einrichtung gezählt |
| niedrig | wget-Befehl beim Enrollment ohne Zertifikatsprüfung | keine wget-Variante bei gepinntem Zertifikat |
| niedrig | API-Schlüssel folgten Weiterleitungen an andere Hosts | keine Weiterleitungen bei API-Clients |
| niedrig | TOTP-Codes mehrfach verwendbar, Fehlversuche ohne Kontosperre | jeder Code nur einmal, Fehlversuche zählen zur Sperre |
| niedrig | Abmelden machte kopierte Sitzungs-Cookies nicht ungültig | Abmelden und Einschalten von 2FA beenden bestehende Sitzungen |
| niedrig | „Konto gesperrt“ verriet vorhandene Benutzernamen | neutrale Meldung |
| niedrig | Sofortlauf eines Wartungsplans durch einen Admin lieh dessen Rechte (Tag-Pläne) | Ziele müssen für Ersteller **und** Ausführenden erlaubt sein |
| niedrig | Rechte auf ein System genügten, um Zabbix-Probleme zu bestätigen/schließen | Zabbix-Aktionen nur mit Rechten auf die Zabbix-Verbindung |
| niedrig | Webhooks ohne Ratenbegrenzung, Zammad-Webhooks wiederholbar | Ratenbegrenzung, Wiederholungen werden erkannt |
| niedrig | Zeilenumbrüche aus Routerdaten im erzeugten RouterOS-Skript | werden maskiert |
| niedrig | SIP-Passwort/Passwort-Hash in der Prozessliste (mysql `-e`), Admin-Passwort der Installation | SQL über stdin, `SM_ADMIN_PASSWORD` statt Argument |
| niedrig | privater TLS-Schlüssel für den Dienstbenutzer lesbar, andere Enrollments für Manager sichtbar | Schlüssel nur root, Liste gefiltert |

Bekannte Restrisiken: Der OIDC-Client-Secret für Nextcloud steht beim Einrichten kurz in der
Kommandozeile von `occ` (die Nextcloud-App bietet keinen anderen Weg); der erste Kontakt zu einem neu
von Hand angelegten System vertraut dem Hostkey (TOFU) – beim Enrollment und bei der Proxmox-Übernahme
wird er dagegen sicher übertragen.
