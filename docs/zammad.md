# Zammad

Unter **Infrastruktur → Zammad** wird ein Zammad-Helpdesk direkt über die REST-API angebunden. Tickets,
die der Servermanager aus Zabbix-Problemen erzeugt, werden dort automatisch angelegt und in **beide
Richtungen** abgeglichen.

## Einrichten

1. In Zammad einen Agenten für den Servermanager anlegen (oder einen vorhandenen nutzen) mit
   Vollzugriff auf die Zielgruppe. Unter *Profil → Token-Zugriff* ein Token mit der Berechtigung
   `ticket.agent` erzeugen – für die automatische Einrichtung des Webhooks zusätzlich
   `admin.webhook` und `admin.trigger`.
2. **Zammad hinzufügen**: Adresse (z. B. `https://support.example.com`), Token, Zertifikat,
   **Gruppe** der Tickets, **Kunde** (E-Mail, z. B. `monitoring@example.com` – wird in Zammad angelegt,
   falls es ihn nicht gibt) und die **Zabbix-Server**, deren Probleme in diesem Zammad landen sollen
   (alternativ in der Zabbix-Verbindung unter *Tickets in Zammad anlegen* auswählen).
3. Unter **Rückmeldung (Webhook) → In Zammad einrichten** legt der Servermanager in Zammad den
   Webhook *Servermanager* (signiert mit einem geheimen Schlüssel) und den Trigger *Servermanager:
   Änderungen zurückmelden* für Tickets mit dem Tag `servermanager` an. Voraussetzung: Die öffentliche
   URL des Servermanagers (Einstellungen → Allgemein) ist von Zammad aus erreichbar.

## Anmeldung über authentik (SSO)

Unter *Infrastruktur → SSO → Anwendungen → Zammad verbinden* richtet der Servermanager die Anmeldung
an Zammad über authentik ein (OpenID Connect). Das Token braucht dafür zusätzlich die Berechtigung
`admin.security`. Details unter [Nextcloud, Mailcow & SSO](apps.md#anwendungen-per-klick-verbinden).

## Eigenes Zammad-Konto je Benutzer

Mit **Im Namen des angemeldeten Benutzers arbeiten** (in der Zammad-Verbindung, ab Werk an) arbeitet
jede Person im Servermanager mit ihrem **eigenen Zammad-Konto und dessen Rechten**. Technisch läuft die
Anfrage über das API-Token mit dem Kopf `X-On-Behalf-Of`. Das Token braucht dafür zusätzlich die
Berechtigung **`admin.user`**.

- **Zuordnung:** Der Servermanager sucht das Zammad-Konto zuerst über den Benutzernamen. Bei Anmeldung
  über authentik ist das der authentik-Benutzername, den Zammad bei der Anmeldung über authentik als
  Login übernimmt. Danach sucht er über die E-Mail-Adresse des Servermanager-Kontos.
  - Die Zuordnung wird gemerkt und nach 24 Stunden erneut geprüft.
  - Wer noch kein Zammad-Konto hat, meldet sich einmal über authentik bei Zammad an. Das Konto entsteht
    dann bzw. wird über die E-Mail-Adresse verknüpft.
- **Im Namen der Person laufen:**
  - Übernehmen: Die Person wird Besitzer.
  - Kommentare als Notiz, Schließen und Wieder öffnen.
  - **Meine Tickets** (Reiter der Zammad-Verbindung): mir zugewiesene offene Tickets und offene Tickets
    ohne Besitzer. Zammad zeigt dort nur, was dieses Konto sehen darf. Die Links öffnen Zammad, die
    Anmeldung dort läuft über authentik.
- **Weiter über das Konto des Tokens:** Tickets aus Zabbix, der regelmäßige Abgleich, Rückmeldungen und
  Personen ohne Zammad-Konto. Die Ticketseite zeigt dann „kein Zammad-Konto“.
- **Reiter Benutzer** (Vollzugriff): alle Servermanager-Benutzer mit ihrem Zammad-Konto und der Art der
  Zuordnung (Benutzername, E-Mail, von Hand), dazu *Alle neu zuordnen*.
  - Ändern dürfen nur **Administratoren**, weil das festlegt, als wer jemand in Zammad handelt:
    *Zuordnen* (Login oder E-Mail eines Zammad-Kontos), *Automatisch* und *Ohne Konto*.
  - Konten ohne Agent-Rolle sind markiert. Sie sehen in Zammad nur eigene Anfragen.

## Abgleich

| Ereignis | Wirkung |
|---|---|
| Neues Problem in Zabbix | Ticket in Zammad: Titel `[SM#Nummer] …`, Priorität nach Schweregrad (Hoch/Katastrophe → *3 high*, Warnung/Durchschnitt → *2 normal*), Tags `servermanager`, `zabbix` und Host, Beschreibung mit Host, Messwerten und Link zum Servermanager |
| Übernehmen im Servermanager | Zammad-Status *offen*, Besitzer = das eigene Zammad-Konto (sonst der Agent mit derselben E-Mail-Adresse) |
| Kommentar im Servermanager | Notiz in Zammad (intern, auf Wunsch öffentlich) |
| Schließen / wieder öffnen im Servermanager | Zammad-Status *geschlossen* / *offen* |
| Zabbix meldet „behoben“ | Notiz in Zammad; mit *automatisch schließen* auch Status *geschlossen* |
| In Zammad geschlossen / wieder geöffnet | Ticket im Servermanager ebenso (Webhook sofort, zusätzlich beim Abgleich) |
| Neue Notiz oder Antwort in Zammad | Eintrag im Verlauf des Servermanager-Tickets (Webhook) |

Eigene Änderungen des Servermanagers werden am Token-Benutzer und am Präfix `[Servermanager]`
erkannt und nicht zurückgespielt, auch wenn sie im Namen einer Person geschrieben wurden. Es entsteht
kein Ping-Pong.

Der **Abgleich** läuft im Intervall der Integrationen und per *Abgleichen*: Er legt Tickets an, deren
Übergabe fehlgeschlagen ist (z. B. Zammad kurz nicht erreichbar), und übernimmt Schließungen – auch
ohne Webhook. Nicht übergebene Tickets stehen in der Übersicht der Zammad-Verbindung und in der
Ticketliste; einzelne Tickets lassen sich mit **An Zammad übergeben** nachreichen.

## Sicherheit

- Das API-Token und das Signatur-Geheimnis des Webhooks werden verschlüsselt gespeichert.
- Eingehende Webhooks werden nur mit gültiger Signatur (`X-Hub-Signature`, HMAC-SHA1) angenommen;
  Fehlversuche zählen zur Sperre nach zu vielen Fehlschlägen.

## Rechte

Die Zammad-Verbindung sehen und abgleichen Benutzer mit Rechten auf die Verbindung
(*Benutzer → Integrationen*). Die Tickets selbst folgen den Rechten aus [Zabbix & Tickets](zabbix.md).
