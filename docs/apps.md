# Nextcloud, Mailcow & SSO

Benutzer in Nextcloud und Mailcow anlegen und verwalten sowie beide per Klick an ein Single Sign-on
(**authentik**) anbinden.

## Erreichbarkeit

| Dienst | intern (Servermanager) | von außen |
|---|---|---|
| authentik | API direkt im internen Netz (z. B. `https://10.20.0.20:9443`) | Anmeldeseite über **Pangolin** (z. B. `https://auth.example.com`) |
| Nextcloud | SSH/`occ` | Weboberfläche über **Pangolin** (z. B. `https://cloud.example.com`) |
| Mailcow | API direkt im internen Netz | Weboberfläche über **Pangolin** (z. B. `https://webmail.example.com`); **IMAP/SMTP über eine eigene Public-IP** (z. B. `mail.example.com`) |

- Die Weboberflächen werden **ohne Pangolin-Anmeldung** veröffentlicht: Die Anwendungen melden selbst an
  bzw. nutzen SSO, und Desktop-/Mobil-Clients (Nextcloud-Sync, ActiveSync, CalDAV) müssen durchkommen.
  Die [Optimierungen](bestand.md) schlagen fehlende Veröffentlichungen vor. Alternativ gibt es auf den
  Seiten von SSO und Mailcow den Button *Über Pangolin veröffentlichen*.
- Für die SSO-Anmeldung werden immer die **öffentlichen** Adressen verwendet, denn die Browser der
  Benutzer müssen die Anmeldeseite erreichen. Nextcloud und Mailcow rufen die Token-Endpunkte von
  authentik ebenfalls über die öffentliche Adresse ab, also über NAT und Pangolin.

## Nextcloud-Benutzer

Auf der System-Seite im Reiter *Nextcloud* → **Benutzer verwalten** (per SSH mit `occ`):

- Liste mit Anzeigename, E-Mail, Gruppen, Quota, Status, letzter Anmeldung.
- **Anlegen** (Vollzugriff): Benutzer-ID, Anzeigename, E-Mail, Gruppen (fehlende werden angelegt), Quota,
  Passwort. Ohne Passwort erzeugt der Servermanager ein zufälliges und zeigt es **einmal** an. Es wird
  nicht gespeichert und nur per Umgebungsvariable an `occ` übergeben (`--password-from-env`).
- **Sperren/Entsperren, neues Passwort** (Bedienen), **Löschen** (Vollzugriff).

> Bei Nextcloud im Docker-Container muss der hinterlegte occ-Befehl die Variable weitergeben, z. B.
> `docker exec -e OC_PASS -u www-data nextcloud php occ`.

## Mailcow

*Infrastruktur → Mailcow* (Verbindung anlegen: Administratoren):

- **API:** interne Adresse und API-Schlüssel (Lese-/Schreibzugriff). In Mailcow unter *Konfiguration →
  Zugang → API* die IP des Servermanagers erlauben.
- **Weboberfläche:** öffentliche Adresse über Pangolin.
- **Mail über eigene Public-IP:** Mail-Hostname (MX, IMAP, SMTP), Public-IP, interne Adresse, Ports
  (Standard `25,465,587,143,993,110,995,4190,80` – Port 80 für das Let's-Encrypt-Zertifikat des
  Mail-Hostnamens) und der zuständige RouterOS. Weboberfläche und Mail-Hostname brauchen
  **verschiedene Namen**, weil der Mail-Hostname auf die Mail-IP zeigt.

Reiter:

- **Postfächer:** anlegen (Adresse, Domain, Name, Quota, Passwort bzw. Zufallspasswort, das einmal
  angezeigt wird), aktivieren/deaktivieren, neues Passwort, löschen.
- **Aliase:** anlegen, löschen.
- **Domains:** Übersicht.
- **Mail-IP & Veröffentlichung:** Konfiguration, Veröffentlichung über Pangolin, SSO-Status.

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

- **Interne Adresse** der API (z. B. `https://10.20.0.20:9443`, Zertifikat per Fingerabdruck gepinnt)
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
- Scheitert die Konfiguration der Anwendung, wird die Anwendung in authentik wieder entfernt.
- **Trennen** entfernt die Anbindung in der Anwendung sowie Provider und Anwendung in authentik.

### Benutzer

Im Reiter *Benutzer*: Liste, **Anlegen** (Benutzername, Name, E-Mail, Gruppen, Passwort bzw.
Zufallspasswort) – optional mit **Postfach auf einer Mailcow** unter der E-Mail-Adresse. Außerdem
aktivieren/deaktivieren, neues Passwort, löschen. Administratorkonten von authentik werden nicht
gelöscht.

## Rechte

| Stufe | Mailcow | SSO | Nextcloud-Benutzer (Recht auf das System) |
|---|---|---|---|
| Lesen | Postfächer, Aliase, Domains ansehen | Anwendungen und Benutzer ansehen | Liste ansehen |
| Bedienen | Postfach aktivieren/deaktivieren, neues Passwort | Benutzer aktivieren/deaktivieren, neues Passwort | sperren/entsperren, neues Passwort |
| Vollzugriff | Postfächer und Aliase anlegen/löschen | Benutzer anlegen/löschen, Anwendungen verbinden/trennen (dazu Vollzugriff auf die Anwendung) | anlegen, löschen |

Alle Aktionen stehen im Audit-Log. Passwörter werden nie gespeichert.
