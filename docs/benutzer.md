# Benutzer und Rechte

| Rolle | Rechte |
|---|---|
| Administrator | alles: alle Systeme, Benutzer, Einstellungen, WireGuard, Backups, Update, Audit-Log |
| Manager | darf Systeme hinzufügen und Enrollment-Tokens erstellen; eigene neue Systeme erhält er mit Vollzugriff |
| Benutzer | nur zugewiesene Systeme |

Zuweisung je System (unter *Benutzer* oder im System unter *Zugriff*):

| Stufe | erlaubt |
|---|---|
| Lesen | Status, Updates, Protokolle ansehen |
| Bedienen | zusätzlich Updates installieren, Dienste/Container/VMs steuern, Neustart, Wartung planen, Konfig-Backups erstellen |
| Vollzugriff | zusätzlich beliebige Befehle, Release-Upgrade, Nextcloud-Core-Update, Zugangsdaten ändern, Backups herunterladen/wiederherstellen, System entfernen (Adresse, Hostkey und geroutete Netze bleiben Administratoren vorbehalten) |

## Gruppen

Unter *Benutzer → Gruppen* bündeln Administratoren Rechte. Eine Gruppe hat Rechte auf:

- **Systeme:** einzelne oder **alle Systeme**.
- **jedes Modul:** Proxmox, RouterOS, Pangolin, Nextcloud, Mailcow, SSO, Telefonie, Zabbix, ISPConfig,
  Zammad, easybell, Hetzner, DNS & Domains. Jeweils einzelne Verbindungen oder **alle** dieser Art.

„Alle“ gilt auch für Systeme und Verbindungen, die später hinzukommen.

**Mitglieder** kommen auf zwei Wegen in eine Gruppe:

- **Von Hand:** in der Gruppe oder im Benutzer unter *Gruppen* angehakt.
- **Über authentik:** Ist der Gruppe eine **authentik-Gruppe** zugeordnet, gehört jeder dazu, der sich
  über authentik anmeldet und Mitglied dieser authentik-Gruppe ist.
  - Die Gruppen kommen bei jeder Anmeldung frisch aus authentik.
  - Bei einer Anmeldung mit Passwort zählen sie nicht.
  - *Aus authentik anlegen* listet die authentik-Gruppen, die noch keiner Gruppe zugeordnet sind. Ein
    Klick legt die passende Gruppe an, danach legst du nur noch die Rechte fest.

**Welches Recht gilt?** Immer das höchste aus den eigenen Rechten des Benutzers und allen seinen Gruppen.
Gruppen machen niemanden zum Administrator. Die Rolle (Administrator, Manager, Benutzer) wird weiter
je Benutzer vergeben.

Die Benutzerliste zeigt zu jedem Benutzer seine Gruppen. Gruppen mit Hetzner-Rechten lassen sich auch
direkt auf der [Hetzner-Seite](hetzner.md#zugriff-uber-authentik) anlegen.

## Anmeldung über authentik (SSO)

Unter *Infrastruktur → SSO → (authentik) → Anwendungen → Anmeldung am Servermanager* richten
Administratoren die Anmeldung per Klick ein: Adresse des Servermanagers angeben (https, so wie im Browser
aufgerufen). Der Servermanager legt in authentik die Anwendung mit der Rückruf-Adresse
`…/login/sso/callback` an und speichert das Client-Geheimnis verschlüsselt. Auf der Anmeldeseite
erscheint danach „Mit *authentik* anmelden“.

- **Zuordnung:** über den Benutzernamen (authentik-Benutzername = Benutzername im Servermanager).
- **Unbekannte Benutzer anlegen** (optional): Konto mit Rolle *Benutzer* ohne Rechte – ein
  Administrator weist danach Systeme zu.
- **Nur Mitglieder einer authentik-Gruppe** (optional).
- **Administratoren** melden sich standardmäßig nur mit Passwort an; per SSO erst nach Freigabe
  („Auch Administratoren dürfen sich per SSO anmelden“). Wer in authentik Benutzer anlegen oder
  umbenennen darf, kann sich sonst als gleichnamiger Administrator anmelden.
- Eine im Servermanager eingerichtete **Zwei-Faktor-Anmeldung** wird auch nach dem SSO-Login abgefragt.
- Die Anmeldung mit Passwort bleibt immer möglich (Notzugang). Rechte vergibt weiterhin der
  Servermanager; deaktivierte oder gesperrte Konten kommen auch per SSO nicht hinein.
- Technik: OpenID Connect (Authorization Code mit PKCE, State und Nonce). Der Code wird über die interne,
  per Fingerabdruck gepinnte Adresse von authentik eingelöst.

## Hetzner

Rechte gibt es für ein ganzes Robot-Konto bzw. Cloud-Projekt oder für einzelne Root- und Cloud-Server, mit den Stufen *Auswerten*,
*Neustarten* und *Ändern*. Details stehen unter [Hetzner](hetzner.md#rechte). Statt je Benutzer lassen sich
diese Rechte auch über [Gruppen](#gruppen) vergeben, auch für authentik-Gruppen, siehe
[Zugriff über authentik](hetzner.md#zugriff-uber-authentik).

## Infrastruktur (Proxmox, RouterOS, Pangolin)

API-Verbindungen legen nur Administratoren an. Anderen Benutzern wird der Zugriff je Verbindung unter
*Benutzer → Infrastruktur (API-Verbindungen)* zugewiesen; ohne Zuweisung ist der Menüpunkt nicht
sichtbar.

| Stufe | Proxmox | RouterOS | Pangolin |
|---|---|---|---|
| Lesen | Gäste, Status, Verlauf, Warnungen | alle Reiter und die Analyse ansehen | Sites und Dienste ansehen |
| Bedienen | Start/Stopp/Neustart, Snapshot erstellen, Sicherung | Lease statisch machen, NAT-Regel ein-/ausschalten, Ping-Test | Dienst aktivieren/deaktivieren |
| Vollzugriff | Container anlegen/löschen, Ressourcen ändern, Snapshots zurückspielen, Überwachung | Leases, NAT, Routen, DNS anlegen/löschen, Konfiguration einlesen und Änderungen anwenden | Dienste veröffentlichen, Ziele und Anmeldung ändern, entfernen |

Rechte für Mailcow und SSO sind in [Nextcloud, Mailcow & SSO](apps.md) beschrieben, die für Telefonanlagen in [Telefonie](telefonie.md), die für Tickets in [Zabbix & Tickets](zabbix.md), die für ISPConfig in [ISPConfig](ispconfig.md), die für Zammad in [Zammad](zammad.md).

Die Seite *Optimierungen* (Scan und Umsetzung über alle Verbindungen) ist Administratoren vorbehalten.
*Bestand übernehmen* erfordert Vollzugriff auf die Proxmox-Verbindung und die Rolle Manager oder
Administrator.

Ist ein System einem Proxmox-Gast zugeordnet (nur durch Administratoren), dürfen Benutzer mit
**Bedienen** auf dieses System den Gast auch ohne Zugriff auf die Proxmox-Verbindung starten,
herunterfahren und neu starten (siehe [Proxmox](proxmox.md)).

Weitere Schutzmechanismen: Sperre nach 8 Fehlversuchen (15 Minuten), Drosselung je IP,
Sitzungsablauf, Invalidierung aller Sitzungen bei Passwortänderung, Audit-Log aller Aktionen.
