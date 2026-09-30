# ISPConfig

Unter **Infrastruktur → ISPConfig** verwaltet der Servermanager ISPConfig-3-Server über die
**Remote-API**: Kunden, Webseiten, E-Mail, DNS und Datenbanken. Die Schnittstelle richtet er per SSH
selbst ein – im Normalfall ganz automatisch beim Hinzufügen des Systems.

## Automatische Einrichtung

1. Den ISPConfig-Server wie jedes andere Gerät als **System** hinzufügen (SSH mit Schlüssel).
2. Bei der ersten Prüfung wird ISPConfig erkannt (Systemmodul *ISPConfig*). Der Servermanager legt dann
   die Verbindung unter *ISPConfig* an und startet den Job **ISPConfig-Schnittstelle einrichten**:
   - Auf dem Server wird der Remote-Benutzer **servermanager** angelegt (bzw. aktualisiert) – mit
     einem zufälligen Passwort (32 Zeichen, als SHA-512-crypt-Hash in der ISPConfig-Datenbank),
     **nur den benötigten Funktionsgruppen** und beschränkt auf die Adresse, mit der der
     Servermanager den Server erreicht.
   - Port und Adresse der Oberfläche werden ermittelt, das (meist selbst signierte) Zertifikat wird
     gepinnt.
   - Die Anmeldung wird getestet, die Daten werden abgefragt.
3. Das Passwort wird nur verschlüsselt im Servermanager gespeichert und nirgends angezeigt.

Abschaltbar unter *Einstellungen → Prüfungen & Jobs* („ISPConfig-Schnittstelle automatisch … einrichten“).
Bereits vorhandene ISPConfig-Systeme erscheinen unter *ISPConfig* als „Erkannte ISPConfig-Systeme ohne
Schnittstelle“ und werden mit **Schnittstelle einrichten** per Klick angebunden.

Alternativ beim Hinzufügen *Vorhandenen Remote-Benutzer eintragen* wählen (API-Adresse
`https://<server>:8080/remote/json.php`, Benutzer, Passwort, Zertifikat) – z. B. wenn kein SSH-Zugang
besteht. In einer **Multiserver-Installation** die Schnittstelle am Master (mit der Oberfläche)
einrichten.

## Funktionen

| Reiter | Anzeige | Aktionen |
|---|---|---|
| Übersicht | Version, Server, Anzahl Kunden/Webseiten/Postfächer/Zonen/Datenbanken, verfügbares ISPConfig-Update | – |
| Kunden | Nummer, Firma, Ansprechpartner, Benutzer, Status | Kunde anlegen (Vollzugriff; unbegrenzte Limits, Standard-Server) |
| Webseiten | Domain, PHP, SSL/Let's Encrypt, Speicher, Status | aktivieren/deaktivieren (Bedienen) |
| E-Mail | Postfächer mit Quota und Zugriff, Mail-Domains mit DKIM | Postfach anlegen, löschen, neues Passwort (Vollzugriff) |
| DNS | Zonen mit Nameserver, Serial, DNSSEC | – |
| Datenbanken | Name, Typ, Fernzugriff | – |
| Zugang | API-Adresse, Benutzer, Zertifikat, Einrichtung | per SSH neu einrichten (neues Passwort); Oberfläche über Pangolin veröffentlichen |

Neue Postfächer und Kunden erhalten ein zufälliges Passwort, wenn keines angegeben ist; es wird nur
einmal angezeigt. Postfächer werden dem Kunden zugeordnet, dem die Mail-Domain gehört.

Updates von ISPConfig selbst, Dienste und Mail-Warteschlange laufen weiter über das Systemmodul
*ISPConfig* (System-Seite, Wartungsplaner).

## Erreichbarkeit

Die Verwaltungsoberfläche (Port 8080) gehört nicht offen ins Internet: unter *Zugang* mit
**Über Pangolin veröffentlichen** (mit Pangolin-Anmeldung) freigeben; die *Optimierungen* schlagen das
ebenfalls vor, sobald eine öffentliche Adresse eingetragen ist. Die Webseiten und Mailserver der Kunden
bleiben auf ihren üblichen Wegen erreichbar.

## Rechte

Wie bei den übrigen Integrationen (*Benutzer → Integrationen*): **Ansehen** zeigt alle Reiter,
**Bedienen** erlaubt Webseiten (de)aktivieren, **Vollzugriff** neue Postfach-Passwörter sowie Kunden und
Postfächer anlegen und löschen. Einrichten und Entfernen der Verbindung: Administratoren.

## Fehlerbehebung

- **„Anmeldung fehlgeschlagen“:** In ISPConfig unter *System → Remote-Benutzer* prüfen, ob
  „servermanager“ existiert, *Remote-Zugriff* aktiv ist und die erlaubte Adresse passt – oder unter
  *Zugang* neu einrichten (ggf. mit anderer erlaubter Adresse).
- **„dem Remote-Benutzer fehlt die Funktion …“:** Nach einem ISPConfig-Update neu einrichten, damit
  neue Funktionsgruppen übernommen werden.
- **Keine Oberfläche gefunden:** Auf einem reinen Server-Knoten einer Multiserver-Installation gibt es
  keine Remote-API – am Master einrichten.
