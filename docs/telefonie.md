# Telefonie: Asterisk & FreePBX

Unter **Infrastruktur → Telefonie** verwaltet der Servermanager Telefonanlagen mit Asterisk – mit
oder ohne FreePBX. Die Anlage wird über ihr **System (SSH)** abgefragt; eine eigene API-Freigabe ist
nicht nötig.

## Zielbild

| Weg | Erreichbarkeit |
|---|---|
| Weboberfläche (FreePBX-Verwaltung, UCP) | über **Pangolin** unter eigenem Namen, mit Pangolin-Anmeldung |
| SIP (Signalisierung) | **Portweiterleitung** am RouterOS, nur für die Adressen des SIP-Providers |
| RTP (Sprache) | **Portweiterleitung** des RTP-Bereichs (UDP) |
| Verwaltung | intern per SSH (WireGuard/Management-Netz) |

SIP und RTP lassen sich nicht sinnvoll durch den Pangolin-Tunnel führen. Sie sind – wie IMAP/SMTP bei
Mailcow – die bewusste Ausnahme vom Ziel „eine Public-IP über Pangolin“. Optional bekommt die Anlage
eine **eigene Public-IP** (dann mit src-NAT für ausgehende Verbindungen).

## Einrichten

1. Die Anlage als **System** hinzufügen (SSH mit Schlüssel). Bei der Prüfung wird das Modul
   *Asterisk/FreePBX* automatisch erkannt.
2. **Telefonie → Telefonanlage hinzufügen:** System wählen, interne IP (wird vom System übernommen),
   SIP-Port, RTP-Bereich, **erlaubte SIP-Gegenstellen** (IP-Adressen/Netze des Providers), RouterOS,
   optional eigene Public-IP sowie interne und öffentliche Adresse der Weboberfläche.
3. Unter **Optimierungen** neu scannen und die Vorschläge für die Telefonanlage bestätigen:
   - **SIP-Helper (SIP-ALG) abschalten** – `/ip firewall service-port set sip disabled=yes`. Der
     Helper schreibt SIP-Pakete um und ist die häufigste Ursache für einseitige Audio.
   - **SIP/RTP-Weiterleitung** – dst-NAT für den SIP-Port (UDP und TCP, optional TLS) nur aus der
     Adressliste `sm-sip-<id>` und für den RTP-Bereich; bei eigener IP zusätzlich die Adresse am WAN
     und ein src-NAT. Vor der Änderung wird auf dem Router eine Sicherung angelegt.
4. In FreePBX unter *Einstellungen → Asterisk SIP Settings* **External Address** (öffentliche
   SIP-Adresse) und **Local Networks** (internes Netz) setzen und den **RTP-Bereich** passend zur
   Weiterleitung einstellen. Der Reiter *SIP & Erreichbarkeit* prüft das und zeigt Abweichungen.
5. Die Weboberfläche über den Knopf *Über Pangolin veröffentlichen* freigeben (mit Pangolin-Anmeldung).

## Reiter

| Reiter | Inhalt |
|---|---|
| Übersicht | Status, Laufzeit, Gespräche, registrierte Trunks, angemeldete Nebenstellen, Modul-Updates |
| Nebenstellen | Liste mit Anmeldestatus, Gerät (IP) und Laufzeit; anlegen, neues SIP-Passwort, löschen |
| Trunks | ausgehende Registrierungen (PJSIP und chan_sip) und weitere Endpunkte mit Zustand |
| SIP & Erreichbarkeit | Weiterleitung, Prüfung der NAT-Einstellungen, Veröffentlichung der Weboberfläche |

## Nebenstellen (FreePBX)

- **Anlegen** (Vollzugriff): Nummer, Name, SIP-Passwort (leer = zufällig, wird **nur einmal**
  angezeigt und nicht gespeichert), optional Voicemail mit PIN und E-Mail. Technik: PJSIP. Benötigt
  das FreePBX-Modul **Bulk Handler** (`fwconsole ma downloadinstall bulkhandler`).
- **Neues SIP-Passwort** (Bedienen): setzt ein zufälliges Passwort; das Telefon muss danach neu
  eingerichtet werden.
- **Löschen** (Vollzugriff): entfernt Benutzer, Gerät und Voicemail-Box.
- Nach jeder Änderung wird die Konfiguration neu geladen (`fwconsole reload`).

Bei reinem Asterisk ohne FreePBX werden Nebenstellen in den Konfigurationsdateien gepflegt; der
Servermanager zeigt dann Status und Anmeldungen an.

## Überwachung

Bei aktivierter Überwachung wird die Anlage im Intervall der Integrationen abgefragt. Warnungen
(Dashboard, auf Wunsch per Mail):

- **Asterisk läuft nicht** (kritisch)
- **Trunk nicht registriert** – mit dem Status des Providers, z. B. *Rejected* (kritisch)
- **Trunk nicht erreichbar** – bei Trunks ohne Registrierung (Qualify) (Warnung)

## Rechte

Wie bei den übrigen Integrationen (*Benutzer → Integrationen*): **Ansehen** zeigt Status, Trunks und
Nebenstellen; **Bedienen** erlaubt Neu laden; **Vollzugriff** neue SIP-Passwörter sowie Anlegen und
Löschen von Nebenstellen. Aktionen auf dem System selbst (Modul-Updates, Neustart) richten sich nach
den Rechten am System.

## Fehlerbehebung

- **Einseitige oder keine Sprache:** SIP-ALG auf dem Router aus? External Address und Local Networks
  gesetzt? RTP-Bereich der Anlage = weitergeleiteter Bereich?
- **Trunk „Rejected“:** Zugangsdaten beim Provider prüfen; bei „No Authentication“/„Unregistered“
  zusätzlich, ob die erlaubten Gegenstellen alle Provider-Adressen enthalten.
- **Nebenstelle anlegen schlägt fehl:** Bulk-Handler-Modul installieren; die Nummer darf nicht bereits
  vergeben sein.
