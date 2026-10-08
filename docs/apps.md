# Nextcloud, Mailcow & SSO

Benutzer in Nextcloud und Mailcow anlegen und verwalten sowie beide (und Pangolin, Proxmox und Zammad) per Klick an
ein Single Sign-on (**authentik**) anbinden.

## Erreichbarkeit

| Dienst | intern (Servermanager) | von außen |
|---|---|---|
| authentik | API direkt im internen Netz (z. B. `https://10.20.0.20:9443`) | Anmeldeseite über **Pangolin** (z. B. `https://auth.example.com`) |
| Nextcloud | Schnittstelle (OCS-API) und/oder SSH/`occ` | Weboberfläche über **Pangolin** (z. B. `https://cloud.example.com`) |
| Mailcow | API direkt im internen Netz | Weboberfläche über **Pangolin** (z. B. `https://webmail.example.com`); **IMAP/SMTP über eine eigene Public-IP** (z. B. `mail.example.com`) |

- Die Weboberflächen werden **ohne Pangolin-Anmeldung** veröffentlicht: Die Anwendungen melden selbst an
  bzw. nutzen SSO, und Desktop-/Mobil-Clients (Nextcloud-Sync, ActiveSync, CalDAV) müssen durchkommen.
  Die [Optimierungen](bestand.md) schlagen fehlende Veröffentlichungen vor. Alternativ gibt es auf den
  Seiten von SSO und Mailcow den Button *Über Pangolin veröffentlichen*.
- Für die SSO-Anmeldung werden immer die **öffentlichen** Adressen verwendet, denn die Browser der
  Benutzer müssen die Anmeldeseite erreichen. Nextcloud und Mailcow rufen die Token-Endpunkte von
  authentik ebenfalls über die öffentliche Adresse ab, also über NAT und Pangolin.

## Nextcloud über die Schnittstelle

*Infrastruktur → Nextcloud* bindet eine Nextcloud über ihre Schnittstelle (OCS-API) an, auch ohne
SSH-Zugang zum Server. Verbindung anlegen (Administratoren):

- **Adresse** der Nextcloud, wie im Browser (z. B. `https://cloud.example.com`), mit
  Zertifikats-Fingerabdruck oder CA-Prüfung.
- **Benutzername** eines Nextcloud-Administrators und ein **App-Passwort**. Das App-Passwort erzeugst du
  in der Nextcloud unter *Persönliche Einstellungen → Sicherheit → Neues App-Passwort erstellen*. Es
  wird verschlüsselt gespeichert.
- Optional das **gleiche System (SSH)**. Darüber laufen Aufgaben, die nur mit `occ` gehen, etwa die
  Anmeldung über authentik.

Reiter:

- **Übersicht** (aus der App *Monitoring*/serverinfo, standardmäßig aktiv): Version und verfügbares
  Update, Benutzer und aktive Benutzer, Dateien, Freigaben, freier Speicher, PHP, Datenbank,
  App-Updates.
- **Benutzer:** Liste mit Speicherbelegung und letzter Anmeldung.
  - Anlegen mit Gruppen und Quota. Ohne Passwort erzeugt der Servermanager ein zufälliges und zeigt es
    einmal an.
  - *Bearbeiten* öffnet ein Fenster für Anzeigename, E-Mail, Quota und Gruppen.
  - Außerdem sperren/entsperren, neues Passwort und löschen.
  - Das Konto der Schnittstelle selbst lässt sich hier weder sperren noch löschen.
- **Gruppen:** Liste mit Mitgliederzahl, Gruppe anlegen.

Konten von Nextcloud-Administratoren (Gruppe `admin`) und die Gruppe `admin` selbst ändern nur
Administratoren des Servermanagers. Die Überwachung warnt bei nicht erreichbarer Schnittstelle und bei
Benutzern über der Belegungsschwelle.

## Nextcloud-Benutzer (SSH)

Auf der System-Seite im Reiter *Nextcloud* → **Benutzer verwalten** (per SSH mit `occ`):

- Liste mit Anzeigename, E-Mail, Gruppen, Quota, Status, letzter Anmeldung.
- **Anlegen** (Vollzugriff): Benutzer-ID, Anzeigename, E-Mail, Gruppen (fehlende werden angelegt), Quota,
  Passwort. Ohne Passwort erzeugt der Servermanager ein zufälliges und zeigt es **einmal** an. Es wird
  nicht gespeichert und nur per Umgebungsvariable an `occ` übergeben (`--password-from-env`).
- **Sperren/Entsperren** (Bedienen), **neues Passwort** und **Löschen** (Vollzugriff).

> Bei Nextcloud im Docker-Container muss der hinterlegte occ-Befehl die Variable weitergeben, z. B.
> `docker exec -e OC_PASS -u www-data nextcloud php occ`.

## Mailcow

*Infrastruktur → Mailcow* (Verbindung anlegen: Administratoren):

- **API:** interne Adresse und API-Schlüssel (Lese-/Schreibzugriff). In Mailcow unter *Konfiguration →
  Zugang → API* die IP des Servermanagers erlauben.
- **Weboberfläche:** öffentliche Adresse über Pangolin.
- **Mail über eigene Public-IP:** Mail-Hostname (MX, IMAP, SMTP), Public-IP, interne Adresse, Ports
  (Standard `25,465,587,143,993,110,995,4190,80` – Port 80 für das Let's-Encrypt-Zertifikat des
  Mail-Hostnamens) und der zuständige RouterOS.
- Solange die Weboberfläche **nicht** über Pangolin läuft, dürfen Weboberfläche und Mailserver
  denselben Namen haben, z. B. beide `mail.example.com` auf der eigenen IP.
- Sobald die Weboberfläche über Pangolin läuft, braucht sie einen **eigenen Namen** (z. B.
  `webmail.example.com`). Ihr DNS-Eintrag zeigt dann auf Pangolin, der Mail-Hostname muss aber
  weiter auf die Mail-IP zeigen. Der Servermanager prüft das beim Speichern, und der Optimierer schlägt
  die Veröffentlichung erst mit eigenem Namen vor.

Reiter:

- **Postfächer:** anlegen (Adresse, Domain, Name, Quota, Passwort bzw. Zufallspasswort, das einmal
  angezeigt wird), aktivieren/deaktivieren, neues Passwort, löschen. *Bearbeiten* in der Zeile öffnet
  ein Fenster, in dem du die Größe (MB) und den Namen des Postfachs änderst.
- **Aliase:** anlegen, löschen.
- **Domains:** Übersicht.
- **Mail-IP & Veröffentlichung:** Konfiguration, Veröffentlichung über Pangolin, SSO-Status.
- **DNS:** MX, SPF, DKIM, DMARC und Autodiscover jeder Mail-Domain im Vergleich mit der Zone beim
  [DNS-Anbieter](dns.md#mail-eintrage-mailcow). Fehlende Einträge legst du per Klick an.

Die Überwachung warnt bei nicht erreichbarer API und bei Postfächern über der Belegungsschwelle.

### Router-Einrichtung für die Mail-IP

Die [Optimierungen](bestand.md) prüfen auf dem zugeordneten RouterOS und legen nach Bestätigung an:

1. die Mail-IP als zusätzliche Adresse (`/32`) am WAN-Interface,
2. eine Portweiterleitung **nur der Mail-Ports** auf dieser IP zu Mailcow,
3. Source-NAT, damit **ausgehende Mails über die Mail-IP** gehen (passend zu PTR und SPF). Die Regel
   wird vor die allgemeine Masquerade-Regel gesetzt.

Diese Portweiterleitungen sind die **bewusste Ausnahme** vom Ziel „eine Public-IP über Pangolin“ und
werden nicht zum Ersetzen vorgeschlagen. Zusätzlich gibt es einen Hinweis auf die DNS-Einträge: PTR der
Mail-IP beim Provider (z. B. Hetzner Robot), MX/A des Mail-Hostnamens, SPF, DKIM und DMARC.

## SSO mit authentik

*Infrastruktur → SSO* (Verbindung anlegen: Administratoren):

- **Interne Adresse** der API (z. B. `https://10.20.0.20:9443`, Zertifikat per Fingerabdruck gepinnt –
  Port 9000 ist der http-Port von authentik und spricht kein https)
  und **API-Token** (authentik: *Verzeichnis → Tokens und App-Passwörter*, Zweck „API“, Benutzer mit
  Administratorrechten).
- **Öffentliche Adresse** der Anmeldeseite über Pangolin (z. B. `https://auth.example.com`).

### Anwendungen per Klick verbinden

Im Reiter *Anwendungen*:

- **Nextcloud verbinden:** Nextcloud wählen, öffentliche Adresse angeben. Der Servermanager legt in
  authentik einen OAuth2/OIDC-Provider und eine Anwendung an (Redirect
  `…/apps/user_oidc/code`). In der Nextcloud installiert und konfiguriert er die App `user_oidc`
  (Benutzer-ID = authentik-Benutzername, Name und E-Mail werden übernommen). Die lokale Anmeldung bleibt
  möglich; SSO-Benutzer werden beim ersten Login angelegt.
- **Mailcow verbinden:** Der Servermanager legt Provider und Anwendung in authentik an und setzt in
  Mailcow den Identity Provider „Generic OIDC“ mit den öffentlichen Endpunkten von authentik
  (Mailcow ab Version 2025-03). Postfächer werden beim ersten SSO-Login angelegt, wenn die Domain
  existiert. IMAP/SMTP-Programme nutzen weiterhin Postfach- bzw. App-Passwörter.
- **Proxmox VE verbinden:** Proxmox-Server wählen und die Adresse der Oberfläche prüfen (vorbelegt
  aus der API-Adresse, z. B. `https://pve.example.com:8006`; dorthin leitet authentik nach dem Login
  zurück).
  - Der Servermanager legt in authentik die Anwendung an und in Proxmox über die API einen
    OpenID-Connect-Realm (Name aus der SSO-Verbindung, z. B. `authentik`).
  - Benutzer melden sich auf der Proxmox-Anmeldeseite mit diesem Realm an, als
    `<authentik-Benutzer>@<realm>`. Beim ersten Login werden sie angelegt, zunächst **ohne Rechte**.
    Rechte vergibst du in Proxmox unter *Rechenzentrum → Berechtigungen*.
  - Optional (ab PVE 8.1): authentik-Gruppen als Proxmox-Gruppen übernehmen. Dann lassen sich Rechte für
    ganze Gruppen vergeben. Ältere Versionen bekommen den Realm ohne Gruppen, das Protokoll sagt es.
  - Optional: den Realm als Standard auf der Anmeldeseite vorwählen.
  - **Voraussetzungen:** Das API-Token braucht `Realm.Allocate` auf `/access/realm` (Rolle
    *Administrator*), und Proxmox muss die öffentliche Adresse von authentik erreichen.
  - Ein vorhandener Realm gleichen Namens vom Typ OpenID wird aktualisiert, einer anderen Typs nie
    angefasst.
  - *Trennen* entfernt Realm und Anwendung. Die angelegten Proxmox-Benutzer bleiben bestehen.
- **Zammad verbinden:** Zammad-Verbindung wählen, Adresse der Oberfläche prüfen.
  - Der Servermanager legt in authentik die Anwendung als **öffentlichen Client mit PKCE** an, denn
    Zammad sendet kein Client-Geheimnis. Die Rückruf-Adresse `…/auth/openid_connect/callback` bildet er
    aus den Zammad-Einstellungen `http_type` und `fqdn`.
  - In Zammad aktiviert er unter *Einstellungen → Sicherheit → Drittanbieter-Anwendungen* die
    Anmeldung über **OpenID Connect** mit dem Namen der SSO-Verbindung. Die Anmeldung mit Passwort
    bleibt möglich.
  - Optional (vorausgewählt): Bestehende Zammad-Konten werden beim ersten Login automatisch verknüpft,
    über den Benutzernamen (= authentik-Benutzername) oder die E-Mail-Adresse.
  - **Voraussetzungen:** Das API-Token der Zammad-Verbindung braucht zusätzlich die Berechtigung
    `admin.security`. Zammad muss die öffentliche Adresse von authentik erreichen, und die Version muss
    OpenID Connect kennen; sonst sagt das Protokoll, was fehlt.
  - *Trennen* schaltet die Anmeldung in Zammad ab und entfernt die Anwendung in authentik. Verknüpfte
    Konten bleiben bestehen.
- **Anmeldung am Servermanager:** siehe [Benutzer und Rechte](benutzer.md#anmeldung-uber-authentik-sso).
- **Pangolin verbinden:** Pangolin-Verbindung wählen, Adresse des Dashboards prüfen (vorbelegt aus der
  API-Adresse, ohne `api.` und Port). Der Servermanager legt in Pangolin einen OIDC-Identity-Provider
  an, in authentik die Anwendung mit der Rückruf-Adresse von Pangolin
  (`…/auth/idp/<ID>/oidc/callback`) und trägt danach Client-ID und Geheimnis in Pangolin ein. Neue
  Benutzer werden beim ersten Login automatisch angelegt und der Organisation als *Member* zugeordnet
  (Rolle in Pangolin unter *Server-Admin → Identity Provider → Organisationsrichtlinien* änderbar).
  Der authentik-Login erscheint auf der Anmeldeseite von Pangolin und damit auch vor jedem Dienst mit
  aktivierter Pangolin-Anmeldung. **Voraussetzung:** Die Pangolin-Verbindung nutzt einen
  **Server-Admin-API-Schlüssel** mit Rechten für Identity Provider – ein Organisations-Schlüssel darf
  keine Identity Provider anlegen (die Meldung sagt das dann).
- Scheitert die Konfiguration der Anwendung, wird die Anwendung in authentik wieder entfernt (bei
  Pangolin auch der Identity Provider).
- **Trennen** entfernt die Anbindung in der Anwendung sowie Provider und Anwendung in authentik.

### Benutzer

Im Reiter *Benutzer*:

- Liste der Benutzer.
- **Anlegen** mit Benutzername, Name, E-Mail, Gruppen und Passwort bzw. Zufallspasswort, optional mit
  **Postfach auf einer Mailcow** unter der E-Mail-Adresse.
- **Bearbeiten** öffnet ein Fenster für Name, E-Mail und die **Gruppen in authentik**. Die Gruppen
  steuern auch die Rechte im Servermanager ([Gruppen](benutzer.md#gruppen)) und in angebundenen
  Anwendungen.
- Außerdem aktivieren/deaktivieren, neues Passwort und löschen.

Administratorkonten von authentik werden nicht gelöscht. Sie und die Administrator-Gruppen von
authentik ändern nur Administratoren des Servermanagers.

### Nextcloud-Benutzer und -Gruppen übernehmen

Bestehende Nextcloud-Konten lassen sich in authentik übernehmen, damit sich die Benutzer danach über
authentik anmelden. Aufruf über *SSO → Benutzer → Nextcloud-Benutzer übernehmen*, auf der Seite einer
Nextcloud-Verbindung (Übersicht) oder auf der Nextcloud-Benutzerseite eines Systems.

1. **Nextcloud wählen:** als Schnittstelle oder als System per SSH.
2. **Vorschau prüfen:**
   - Welche Gruppen neu angelegt werden und welche es in authentik schon gibt (Vergleich ohne Groß- und
     Kleinschreibung).
   - Welche Benutzer neu angelegt werden und welche es schon gibt.
   - Welche Benutzer-IDs authentik nicht erlaubt, z. B. mit Leerzeichen.
3. **Auswahl anpassen und übernehmen.** Vorausgewählt sind alle Gruppen außer `admin` und alle aktiven
   Benutzer, die es in authentik noch nicht gibt.

Ergebnis:

- Die Gruppen entstehen in authentik unter demselben Namen, ohne Administratorrechte.
- Neue Benutzer bekommen die Nextcloud-Benutzer-ID als Benutzernamen, dazu Anzeigename und E-Mail.
  Gesperrte Nextcloud-Benutzer werden, falls ausgewählt, deaktiviert angelegt.
- Die Mitgliedschaften werden ergänzt, auf Wunsch auch für Benutzer, die es in authentik schon gab.
- **Passwörter:** Entweder ein zufälliges Startpasswort je Benutzer, das nur auf der Ergebnisseite
  angezeigt wird (mit *Liste kopieren*), oder kein Passwort. Dann setzen die Benutzer es über „Passwort
  vergessen“, sofern in authentik ein Wiederherstellungs-Flow eingerichtet ist.
- In authentik wird nichts gelöscht, in der Nextcloud nichts geändert. Ein zweiter Durchgang ergänzt
  nur, was fehlt. Je Durchgang werden höchstens 300 Benutzer angelegt.

**Anmeldung danach:** Die SSO-Anbindung der Nextcloud (App `user_oidc`) nimmt den authentik-Benutzernamen
als Nextcloud-Benutzer-ID. Gibt es das Konto schon, wird es übernommen, statt ein neues anzulegen
(„soft auto provisioning“, der Servermanager setzt es beim Verbinden ausdrücklich). Die Benutzer landen
also in ihrem bestehenden Konto mit allen Dateien und Freigaben. Die Gruppen in der Nextcloud bleiben
wie sie sind.

Die Übernahme braucht Vollzugriff auf die SSO-Verbindung und Leserecht auf die Nextcloud.
Nextcloud-Administratoren und die Gruppe `admin` übernehmen nur Administratoren des Servermanagers:
Ein authentik-Konto mit gleichem Namen öffnet über SSO das Administratorkonto der Nextcloud.

## Rechte

| Stufe | Mailcow | SSO | Nextcloud (Schnittstelle) | Nextcloud-Benutzer (Recht auf das System) |
|---|---|---|---|---|
| Lesen | Postfächer, Aliase, Domains ansehen | Anwendungen und Benutzer ansehen | Übersicht, Benutzer, Gruppen ansehen | Liste ansehen |
| Bedienen | Postfach aktivieren/deaktivieren | Benutzer aktivieren/deaktivieren (keine Admin-Konten) | Benutzer sperren/entsperren, aktualisieren | sperren/entsperren, Quota |
| Vollzugriff | Postfächer und Aliase anlegen/löschen, Postfach bearbeiten (Größe, Name), neues Passwort | Benutzer anlegen/löschen, neues Passwort (Admin-Konten nur für Administratoren des Servermanagers), Anwendungen verbinden/trennen (dazu Vollzugriff auf die Anwendung), Nextcloud-Benutzer übernehmen | Benutzer anlegen, bearbeiten, löschen, neues Passwort, Gruppen anlegen (Nextcloud-Admins nur für Administratoren des Servermanagers) | anlegen, löschen, neues Passwort |

Ein neues Passwort ist eine Kontoübernahme (wer es setzt, kann sich als dieser Benutzer anmelden) und
erfordert deshalb überall Vollzugriff.

Alle Aktionen stehen im Audit-Log. Passwörter werden nie gespeichert.
