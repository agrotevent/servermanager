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

## Abgleich

| Ereignis | Wirkung |
|---|---|
| Neues Problem in Zabbix | Ticket in Zammad: Titel `[SM#Nummer] …`, Priorität nach Schweregrad (Hoch/Katastrophe → *3 high*, Warnung/Durchschnitt → *2 normal*), Tags `servermanager`, `zabbix` und Host, Beschreibung mit Host, Messwerten und Link zum Servermanager |
| Übernehmen im Servermanager | Zammad-Status *offen*, Besitzer = Agent mit derselben E-Mail-Adresse wie der Benutzer |
| Kommentar im Servermanager | Notiz in Zammad (intern, auf Wunsch öffentlich) |
| Schließen / wieder öffnen im Servermanager | Zammad-Status *geschlossen* / *offen* |
| Zabbix meldet „behoben“ | Notiz in Zammad; mit *automatisch schließen* auch Status *geschlossen* |
| In Zammad geschlossen / wieder geöffnet | Ticket im Servermanager ebenso (Webhook sofort, zusätzlich beim Abgleich) |
| Neue Notiz oder Antwort in Zammad | Eintrag im Verlauf des Servermanager-Tickets (Webhook) |

Eigene Änderungen des Servermanagers werden am Token-Benutzer und am Präfix `[Servermanager]`
erkannt und nicht zurückgespielt – es entsteht kein Ping-Pong.

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
