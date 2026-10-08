# CloudPanel

[CloudPanel](https://www.cloudpanel.io) (v2) verwaltet Sites (PHP, Node.js, Python, statisch,
Reverse-Proxy) mit nginx, Datenbanken und Let's-Encrypt-Zertifikaten. Es hat **keine REST-API**. Der
Servermanager steuert es deshalb per **SSH** mit dem mitgelieferten Kommandozeilenwerkzeug `clpctl`.

## Einrichten

1. Den CloudPanel-Server wie jedes System unter *Systeme* mit SSH-Zugang (root oder sudo) anlegen.
2. Bei der Bestandsaufnahme erkennt der Servermanager CloudPanel an `clpctl` und setzt den Typ
   **CloudPanel**, oder du setzt ihn im System unter *Bearbeiten*.
3. Der Server erscheint unter **Infrastruktur → CloudPanel**.

Die Listen liest der Servermanager nur lesend aus CloudPanels eigener Datenbank
(`/home/clp/htdocs/app/data/db.sq3`), **ohne** Spalten mit Passwörtern, Schlüsseln oder MFA-Geheimnissen.
Dafür braucht der Server `python3`. Ohne `python3` erscheinen nur die Sites aus der nginx-Konfiguration.
Die Laufzeit der Zertifikate kommt aus `/etc/nginx/ssl-certificates/`.

## Funktionen

| Reiter | Inhalt | Aktionen |
|---|---|---|
| Sites | Domain, Typ, PHP-Version, Site-Benutzer, Zertifikat mit Laufzeit | **Neue Site** (PHP mit Vhost-Vorlage, Node.js, Python, statisch, Reverse-Proxy), **Let's Encrypt** ausstellen, Site **löschen** |
| Datenbanken | Datenbank, Site, Benutzer | **Neue Datenbank** mit Datenbank-Benutzer |
| Benutzer | Benutzer der CloudPanel-Oberfläche mit Rolle | **Neuer Benutzer** (Benutzer mit gewählten Sites, Site-Manager, Administrator), neues Passwort, Zwei-Faktor abschalten, löschen, **Aus authentik anlegen** |
| Zugang & authentik | Veröffentlichung über Pangolin mit authentik | *Über Pangolin veröffentlichen* |

Auf der Seite des Systems stehen zusätzlich *CloudPanel aktualisieren* (`clp-update`) und
*Cloudflare-IPs aktualisieren*. Beide lassen sich auch im Wartungsplaner einplanen.

**Passwörter** für Site-Benutzer, Datenbank-Benutzer und CloudPanel-Benutzer erzeugt der Servermanager.
Sie werden **nur einmal angezeigt** und nicht gespeichert. `clpctl` bekommt sie als Argument, deshalb
sind sie während des Aufrufs für root in der Prozessliste sichtbar, wie bei jeder Nutzung von `clpctl`.

## authentik

CloudPanel kennt keine Anmeldung über OpenID Connect oder SAML. Die Anbindung an authentik läuft über
Pangolin:

1. *Zugang & authentik → Über Pangolin veröffentlichen*: die Oberfläche (`https://<host>:8443`)
   **mit Pangolin-Anmeldung** veröffentlichen, z. B. als `cloudpanel.example.com`. Vor CloudPanel steht
   dann die Anmeldung über authentik.
2. Auf der Seite des veröffentlichten Dienstes unter **Zugriff (Rollen)** nur die passende Pangolin-Rolle
   zulassen. Welche authentik-Gruppe welche Rolle bekommt, legst du auf der Seite der
   Pangolin-Verbindung fest ([Pangolin](pangolin.md#anmeldung-uber-authentik-sso)).
3. Danach meldet man sich mit dem CloudPanel-Konto an. **Aus authentik anlegen** (Reiter Benutzer)
   erzeugt CloudPanel-Konten mit gleichem Benutzernamen und gleicher E-Mail-Adresse wie in authentik,
   mit Auswahl, Rolle und Startpasswort (einmal angezeigt).
4. Port 8443 danach nicht mehr direkt aus dem Internet erreichbar machen (Router/Firewall).

## Rechte

Es gelten die Rechte auf das **System**:

| Stufe | Darf |
|---|---|
| Lesen | Sites, Datenbanken und Benutzer ansehen |
| Bedienen | zusätzlich Let's-Encrypt-Zertifikate ausstellen, Cloudflare-IPs aktualisieren |
| Vollzugriff | Sites, Datenbanken und Benutzer anlegen und löschen, Passwörter setzen, Zwei-Faktor abschalten, CloudPanel aktualisieren, Benutzer aus authentik anlegen (dazu Vollzugriff auf die SSO-Verbindung) |

**CloudPanel-Administratoren** anlegen, ändern oder löschen nur Administratoren des Servermanagers.
Alle Aktionen stehen im Audit-Log. Das Modul lässt sich unter *Einstellungen → Module* ausblenden.
