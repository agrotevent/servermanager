# Zabbix & Tickets

> Das Modul ist ab Werk **ausgeblendet**. Einblenden unter *Einstellungen → Module → Zabbix & Tickets*
> ([Module ausblenden](oberflaeche.md#module-ausblenden)).

Unter **Infrastruktur → Zabbix** wird ein Zabbix-Server (6.0 LTS bis 7.x) angebunden. Der
Servermanager richtet auf den verwalteten Systemen den **Zabbix-Agent 2** mit PSK-Verschlüsselung ein,
legt die Hosts in Zabbix an und macht aus Problemen **Tickets**, die im Servermanager bearbeitet und an
Zabbix zurückgemeldet werden.

## Verbindung einrichten

1. In Zabbix unter *Benutzer → API-Token* ein Token erzeugen. Für die Hosts genügt die Rolle *Admin*;
   für die automatische Einrichtung der Ticket-Schnittstelle (Medientyp, Benutzer, Aktion) wird
   *Super Admin* benötigt.
2. **Zabbix hinzufügen**: Adresse (Weboberfläche oder direkt `…/api_jsonrpc.php`), API-Token,
   Zertifikat (Fingerabdruck pinnen oder System-CAs).
3. **Zabbix-Server für die Agenten**: Adresse, unter der die Agenten den Server oder Proxy erreichen
   (wird als `Server`/`ServerActive` eingetragen), z. B. die interne IP des Zabbix-Servers.
4. **Host-Gruppe** (Standard `Servermanager`), **Tickets ab Schweregrad** (Standard *Warnung*) und
   optional die E-Mail-Adresse eines externen **Ticketsystems**.

## Hosts & Agenten

Im Reiter *Hosts & Agenten* stehen alle Systeme mit ihrem Zustand in Zabbix. **In Zabbix aufnehmen**
startet je System einen Job, der

- per SSH den Zabbix-Agent 2 installiert (offizielle Zabbix-Paketquelle passend zur Server-Version,
  sonst das Paket der Distribution; Debian/Ubuntu),
- einen eigenen **PSK** (256 Bit) erzeugt – verschlüsselt im Servermanager gespeichert, auf dem System
  in `/etc/zabbix/servermanager.psk` (nur root/zabbix lesbar), im Protokoll ausgeblendet,
- die Agent-Konfiguration in `/etc/zabbix/servermanager-agent2.conf` schreibt (die entsprechenden
  Zeilen der Hauptkonfiguration werden auskommentiert, das Original bleibt als
  `zabbix_agent2.conf.servermanager-orig` erhalten),
- bei Docker-Systemen den Benutzer `zabbix` in die Gruppe `docker` aufnimmt,
- den Host in Zabbix anlegt bzw. aktualisiert: Agent-Schnittstelle (Adresse aus der Tabelle, Port
  10050), PSK-Verschlüsselung in beide Richtungen, Host-Gruppe, Vorlagen *Linux by Zabbix agent* und bei
  Docker *Docker by Zabbix agent 2*. Vorhandene Gruppen und Vorlagen des Hosts bleiben erhalten.

Erneut ausführen aktualisiert Agent und Host und behält den PSK. Der Zabbix-Server muss die Agenten
auf Port 10050/tcp erreichen, die Agenten den Server auf 10051/tcp (aktive Prüfungen).

## Tickets

Ein Ticket entsteht für jedes Problem ab dem eingestellten Schweregrad – auf zwei Wegen:

- **Webhook (sofort):** *Ticket-Schnittstelle → In Zabbix einrichten* legt in Zabbix den Medientyp
  *Servermanager Tickets*, die Benutzergruppe und den Benutzer *servermanager-tickets* (ohne Zugang zur
  Weboberfläche, mit Lesezugriff auf die Host-Gruppen, zufälliges Passwort, das nicht gespeichert wird)
  und die Aktion *Servermanager: Probleme als Tickets* an. Zabbix meldet Probleme, Behebungen und
  Aktualisierungen an `https://<servermanager>/api/zabbix/<id>/event`. Die Übergabe ist mit einem Token
  gesichert, das im Servermanager nur als Hash liegt; *Neu einrichten* erzeugt ein neues Token und
  aktualisiert die Objekte in Zabbix. Voraussetzung: die öffentliche URL (Einstellungen → Allgemein)
  ist von Zabbix aus erreichbar. Neu angelegte Host-Gruppen erfordern ein erneutes Einrichten.
- **Abgleich:** Bei jeder Abfrage der Verbindung (Intervall der Integrationen) und per *Abgleichen*
  werden fehlende Tickets angelegt und Tickets zu nicht mehr bestehenden Problemen als *Behoben*
  markiert. Das funktioniert auch ohne Webhook.

Tickets werden über den Host-Namen oder die IP-Adresse einem **System** zugeordnet und dort auf der
Übersicht angezeigt.

### Bearbeiten

Menü **Tickets** (mit Zähler der aktiven Tickets):

| Aktion | Wirkung im Servermanager | Rückmeldung an Zabbix |
|---|---|---|
| Übernehmen | Bearbeiter = ich, Status *In Bearbeitung* | Problem bestätigt (Acknowledge) mit Nachricht |
| Kommentar | Eintrag im Verlauf | optional als Nachricht am Problem |
| Schließen | Status *Geschlossen* mit Notiz | optional Problem schließen – nur wenn der Trigger manuelles Schließen erlaubt |
| Wieder öffnen | Status *Offen*/*In Bearbeitung* | – |
| Zuweisen (Admins) | Bearbeiter setzen | – |

Nachrichten, die in Zabbix an einem Problem hinterlassen werden, erscheinen im Verlauf des Tickets.
Behebt Zabbix das Problem, wird das Ticket *Behoben*.

### Zammad

Tickets können direkt in einem Zammad angelegt und in beide Richtungen abgeglichen werden – siehe
[Zammad](zammad.md). Dazu in der Zabbix-Verbindung *Tickets in Zammad anlegen* wählen.

### Andere Ticketsysteme (E-Mail)

Ist eine Adresse für das Ticketsystem hinterlegt (Zammad, OTRS/Znuny, osTicket …), gehen neue,
behobene und geschlossene Tickets dorthin per E-Mail mit `[SM#<Nummer>]` im Betreff, damit das
Ticketsystem sie demselben Vorgang zuordnet. Bei aktivierten Benachrichtigungen (Einstellungen) gehen
sie außerdem an die Admin-Empfänger, Behebungen und Abschlüsse auch an den Bearbeiter.

## Rechte

Tickets sieht, wer das zugeordnete System oder die Zabbix-Verbindung sehen darf; bearbeiten darf, wer
dort mindestens **Bedienen** hat. Agenten einrichten erfordert Vollzugriff auf die Zabbix-Verbindung und
das jeweilige System.
