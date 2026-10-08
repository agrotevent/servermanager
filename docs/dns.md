# DNS & Domains

Unter **Infrastruktur → DNS & Domains** bindet der Servermanager Konten bei Domain-Anbietern an. Er zeigt
Domains und DNS-Zonen, pflegt Einträge und legt die Einträge für [Pangolin](pangolin.md) und Mail
([Mailcow](apps.md#mailcow)) an.

Unterstützte Anbieter:

| Anbieter | Adresse der Schnittstelle | Zugang |
|---|---|---|
| **hosting.de-Plattform**: FRESH Internet, hosting.de, http.net | z. B. `https://secure.fresh-internet.de` | API-Schlüssel aus dem Kundenportal |
| **INWX** | `https://api.domrobot.com` | Benutzername und Passwort, optional Zwei-Faktor |

Die Adresse ist einstellbar. FRESH Internet läuft auf der Plattform von hosting.de und nutzt dieselbe
Schnittstelle unter der eigenen Adresse.

## Einrichten

*Anbieter anbinden* (nur Administratoren), oben den Anbieter wählen:

- **hosting.de-Plattform:**
  - Adresse, für FRESH Internet `https://secure.fresh-internet.de`.
  - **API-Schlüssel** aus dem Kundenportal, mit Rechten für DNS und Domains. Fehlen die Rechte für
    Domains, erscheinen nur die Zonen. Die Seite sagt dann, warum.
- **INWX:**
  - Am besten ein eigener API-Benutzer (*Konto → Benutzer*) mit Benutzername und Passwort.
  - Ist die Zwei-Faktor-Anmeldung aktiv, den **geheimen Schlüssel** aus dem QR-Code hinterlegen. Die
    Codes berechnet der Servermanager selbst.
  - Die Sitzung wird zehn Minuten weiterverwendet. INWX lehnt einen schon benutzten Code ab, deshalb
    wartet der Servermanager notfalls bis zum nächsten Code.
- **Für beide gilt:**
  - Das Zertifikat wird über die System-CAs geprüft oder per Fingerabdruck festgeschrieben.
  - TTL neuer Einträge (Standard 3600 s).
  - Vorwarnzeit für ablaufende Domains (Standard 30 Tage).
  - *DNS für Pangolin automatisch*: siehe unten.

Zugangsdaten werden verschlüsselt gespeichert.

## Domains

Der Reiter **Domains** zeigt jede Domain mit Status, Laufzeitende, Art der Verlängerung, Nameservern
und Transfersperre. Läuft eine Domain innerhalb der Vorwarnzeit aus und wird **nicht verlängert**
(gekündigt bzw. bei INWX *AUTODELETE*/*AUTOEXPIRE*), warnt die Überwachung, ebenso bei einem
ungewöhnlichen Status. Automatisch verlängerte Domains erscheinen nur in der Liste („Läuft bald ab“).

## Zonen und Einträge

Der Reiter **Zonen** listet die DNS-Zonen. Ein Klick zeigt die Einträge:

- **Anlegen:** Name relativ zur Zone (`www`; `@` = die Zone selbst), Typ (A, AAAA, CNAME, MX, TXT,
  SRV, CAA, NS, PTR), Inhalt, Priorität für MX/SRV, TTL.
  - TXT gibst du ohne Anführungszeichen ein. Lange Texte teilt der Servermanager selbst auf.
  - SRV: Inhalt „Gewicht Port Ziel“, die Priorität steht separat.
- **Bearbeiten** öffnet ein Fenster mit allen Feldern. **Löschen** fragt nach.
- Die NS-Einträge der Zone selbst bleiben unangetastet.
- Neben einem CNAME lässt der Servermanager unter demselben Namen keine weiteren Einträge zu.

Jede Änderung steht im Audit-Log.

## DNS für Pangolin

Ein über Pangolin veröffentlichter Name braucht einen DNS-Eintrag, der auf Pangolin zeigt. Das Ziel
legst du in der Pangolin-Verbindung fest (*DNS-Ziel veröffentlichter Namen*):

- **Ein Hostname** ergibt einen **CNAME**.
- **Eine IP-Adresse** ergibt einen **A-** bzw. **AAAA-Eintrag**.
- **Leer:** Ziel ist die Adresse des Pangolin-Dashboards.

So arbeitet der Servermanager damit:

- **Automatisch beim Veröffentlichen:** Liegt der Name in einer Zone einer DNS-Verbindung mit *DNS für
  Pangolin automatisch*, legt er den fehlenden Eintrag an. Das gilt für die Seite *Veröffentlichen* und
  für neue Container. Ein passender Platzhalter (`*.zone`) genügt. Zeigt ein vorhandener Eintrag
  woandershin, meldet er das, ändert aber nichts.
- **Prüfung bestehender Namen:** Der Reiter **Prüfung** zeigt alle veröffentlichten Namen in den Zonen
  der Verbindung und ihren Status. *Anlegen* ergänzt fehlende Einträge, *Ersetzen* korrigiert
  abweichende.

## Mail-Einträge (Mailcow)

Auf der Seite einer Mailcow zeigt der Reiter **DNS** für jede aktive Mail-Domain die erwarteten
Einträge im Vergleich mit der Zone:

| Eintrag | erwartet |
|---|---|
| Mail-Hostname | A auf die eigene Mail-IP |
| MX | `10 <Mail-Hostname>` |
| SPF (TXT) | genau ein `v=spf1`-Eintrag mit `mx`, der Mail-IP oder einem include; neu: `v=spf1 mx ip4:<Mail-IP> -all` |
| DKIM (TXT) | `<Selector>._domainkey` mit dem Schlüssel aus Mailcow |
| DMARC (TXT) | `_dmarc` mit `v=DMARC1`; neu: `v=DMARC1; p=quarantine` |
| Autodiscover/Autoconfig | CNAME auf den Mail-Hostnamen |
| `_autodiscover._tcp` (SRV) | `0 1 443 <Mail-Hostname>` |

- **Anlegen** schreibt einen fehlenden Eintrag.
- **Ersetzen** tauscht einen abweichenden aus. Bei TXT betrifft das nur den Eintrag derselben Art (SPF,
  DKIM oder DMARC).
- **DKIM:** Hat Mailcow für eine Domain noch keinen Schlüssel, steht ein Hinweis da. Den Schlüssel
  erzeugst du in Mailcow unter *Konfiguration → ARC/DKIM-Keys*.
- **PTR:** Den PTR der Mail-IP setzt du beim Anbieter der IP, bei Hetzner auf der
  [Server-Seite](hetzner.md).

## Rechte

| Stufe | erlaubt |
|---|---|
| Lesen | Domains, Zonen, Einträge und Prüfungen ansehen |
| Bedienen | aktualisieren; **fehlende** Einträge aus den Prüfungen (Pangolin, Mail) anlegen |
| Vollzugriff | Einträge frei anlegen, ändern, löschen; abweichende Einträge aus den Prüfungen ersetzen |

Verbindungen anlegen, bearbeiten und entfernen dürfen nur Administratoren. Die Mail-Prüfung zeigt nur
Zonen von Verbindungen, die der Benutzer sehen darf.
