# Änderungsprotokoll

Alle wesentlichen Änderungen am Servermanager. Neue Einträge stehen oben.

## 1.23.0 – 08.10.2026

### Neu

- **Gruppen in der Benutzerverwaltung** mit Rechten auf Systeme und auf jedes Modul (einzeln oder
  „alle“, auch künftige). Mitglieder kommen von Hand oder über eine **authentik-Gruppe** bei der
  Anmeldung über authentik. *Aus authentik anlegen* übernimmt authentik-Gruppen per Klick. Es gilt das
  höchste Recht aus eigenen Rechten und Gruppen.
- **SSO → Benutzer → Bearbeiten**: Name, E-Mail und Gruppen eines authentik-Benutzers im Fenster
  ändern. Administrator-Gruppen vergeben nur Administratoren.

### Geändert

- Die Hetzner-Rechte über authentik-Gruppen (1.21) gehen in den Gruppen auf und werden beim Update
  übernommen. Auf der Hetzner-Seite gibt es zusätzlich das Ziel „alle Robot-Konten bzw. Cloud-Projekte“.

## 1.22.0 – 08.10.2026

### Neu

- **DNS & Domains** unter Infrastruktur, für die **hosting.de-Plattform** (FRESH Internet unter
  `secure.fresh-internet.de`, hosting.de, http.net) und **INWX**, auch mit Zwei-Faktor:
  - Domains mit Status, Laufzeit und Nameservern; Warnung, wenn eine Domain bald ausläuft und nicht
    verlängert wird.
  - Zonen und Einträge ansehen, anlegen, bearbeiten (Fenster) und löschen.
  - Rechte Lesen, Bedienen und Vollzugriff.
- **DNS für Pangolin:** Beim Veröffentlichen legt der Servermanager den Eintrag in der passenden Zone
  automatisch an (CNAME bzw. A/AAAA auf das neue *DNS-Ziel* der Pangolin-Verbindung). Eine Prüfung zeigt
  den Stand aller veröffentlichten Namen, fehlende und abweichende Einträge lassen sich per Klick
  korrigieren.
- **Mail-DNS für Mailcow:** Der neue Reiter *DNS* prüft für jede Mail-Domain A des Mail-Hostnamens, MX,
  SPF, DKIM (Schlüssel aus Mailcow), DMARC sowie Autodiscover/Autoconfig. Fehlende Einträge legst du per
  Klick an.

## 1.21.0 – 08.10.2026

### Neu

- **Hetzner: Rechte über authentik-Gruppen.** Eine authentik-Gruppe bekommt *Auswerten*, *Neustarten*
  oder *Ändern* auf ein Robot-Konto, einen Root-Server, ein Cloud-Projekt oder einen Cloud-Server. Das
  gilt für Anmeldungen über authentik; die Gruppen kommen bei jeder Anmeldung frisch aus authentik.
- **Hetzner: Kachel im authentik-Portal.** Ein Klick meldet über authentik am Servermanager an und öffnet
  die Hetzner-Seite. Auf Wunsch sehen sie nur die Mitglieder der zugeordneten Gruppen.
- Die Benutzerseite zeigt die authentik-Gruppen der letzten Anmeldung über authentik.

### Geändert

- `/login/sso` leitet bei bestehender Sitzung direkt auf die gewünschte Seite weiter.

## 1.20.0 – 08.10.2026

### Neu

- **Nextcloud unter Infrastruktur** über die Schnittstelle (OCS-API), mit Administrator-Konto und
  App-Passwort, auch ohne SSH-Zugang:
  - Übersicht: Version und Updates, Benutzer, aktive Benutzer, Speicher.
  - Benutzer anlegen, bearbeiten (Fenster für Anzeigename, E-Mail, Quota, Gruppen), sperren, neues
    Passwort, löschen.
  - Gruppen anzeigen und anlegen.
  - Überwachung mit Warnung bei vollen Benutzerspeichern.
  - Eigene Rechte (Lesen, Bedienen, Vollzugriff).
- **Nextcloud-Benutzer und -Gruppen nach authentik übernehmen**, mit Vorschau:
  - Gruppen werden unter demselben Namen angelegt, fehlende Benutzer mit der Nextcloud-Benutzer-ID.
  - Die Mitgliedschaften werden ergänzt; Startpasswörter erscheinen einmal.
  - Danach landen die Benutzer beim Login über authentik in ihrem bestehenden Nextcloud-Konto.
- **Zammad per Klick an authentik anbinden** (OpenID Connect). Bestehende Zammad-Konten werden beim
  ersten Login verknüpft.

### Geändert

- Die SSO-Anbindung einer Nextcloud setzt jetzt ausdrücklich, dass bestehende Konten übernommen werden
  (`soft_auto_provision`).

## 1.19.2 – 08.10.2026

### Behoben

- ISPConfig: Die Abfrage der Kunden schlug mit „client_get: The ID must be either an integer or an
  array.“ fehl. ISPConfig erwartet bei dieser Funktion den Parameter `client_id` statt `primary_id`.

## 1.19.1 – 08.10.2026

### Geändert

- Mailcow: Postfächer bearbeitest du jetzt über den Button **Bearbeiten** in der Zeile, neben
  *Deaktivieren* und *Neues Passwort*. Er öffnet ein Fenster mit der Größe (MB) und dem Namen. Das
  aufklappbare Formular unter jeder Adresse entfällt.

## 1.19.0 – 07.10.2026

### Geändert

- **Setnetz-CI als Standard-Design:**
  - Farben aus dem Setnetz-Designsystem: brand-blue als Aktionsfarbe, brand-navy für Seitenleiste und
    Anmeldeseite, brand-sky als Akzent auf Navy.
  - Schriften: IBM Plex Sans, Überschriften in Barlow Condensed (Großbuchstaben), Beschriftungen in
    IBM Plex Mono. Die Schriften werden mitgeliefert, es gibt keine externen Quellen.
  - Flache Flächen ohne Verläufe und Schatten, Radien 4/6 px.
  - Setnetz-Logo in der Seitenleiste (negativ) und auf der Anmeldekarte (positiv).
  - Dunkelmodus in Navy-Tönen.
- Unter *Einstellungen → Erscheinungsbild* lassen sich Farben, Schrift und Logo weiterhin überschreiben.
  Das Setnetz-Logo lässt sich abschalten.

## 1.18.0 – 07.10.2026

### Neu

- **Erscheinungsbild (Corporate Design)** unter *Einstellungen*:
  - Hauptfarbe, Farbe der Seitenleiste und Akzentfarbe; Varianten und Kontraste werden automatisch
    abgeleitet.
  - Logo (dazu optional eine Variante für helle Hintergründe) für Seitenleiste, Anmeldeseite und
    Browser-Symbol.
  - Schrift, auch als eigene Schriftdatei.

  Alles wird vom Servermanager selbst ausgeliefert und ist im Backup enthalten. Details unter
  [Oberfläche](oberflaeche.md#erscheinungsbild-corporate-design).

## 1.17.5 – 06.10.2026

### Behoben

- ISPConfig: Die automatische Einrichtung scheiterte, wenn die Oberfläche unter der Adresse des Systems
  nicht erreichbar ist (z. B. „176.9.57.106:8080 nicht erreichbar: timed out“).
  - Im SSH-Modus lässt sich jetzt eine eigene **API-Adresse** mit Port angeben, optional mit CA-Prüfung
    für Let's-Encrypt-Zertifikate.
  - Die Zugangsdaten werden vor dem Verbindungstest gespeichert. Nach einem Fehlschlag reicht es, die
    Adresse einzutragen.
- Mailcow: Beim Ändern der Postfachgröße meldete der Browser „Gültigen Wert eingeben“, wenn die Zahl kein
  Vielfaches von 256 war. Jetzt ist jede ganze Zahl in MB gültig.

## 1.17.4 – 06.10.2026

### Behoben

- easybell: „Verbindung steht, aber keine Begrüßung vom Server“. Port 5039 ist bei Asterisk der Port
  für AMI über TLS, der Servermanager konnte bisher nur unverschlüsselt.
  - Neue Einstellung *Verbindung*: *automatisch* (Standard) versucht TLS mit Zertifikatsprüfung und nimmt
    sonst die unverschlüsselte Verbindung. Daneben gibt es *nur TLS* und *unverschlüsselt*.
  - Bei einem ungültigen Zertifikat wird nicht auf unverschlüsselt ausgewichen.
  - Die Detailseite zeigt, welche Verbindung läuft.

## 1.17.3 – 06.10.2026

### Neu

- Mailcow: Bestehende Postfächer lassen sich bearbeiten: **Größe** (MB) und Anzeigename (Vollzugriff).
  Überschreitet die Größe die Grenzen der Domain, sagt die Meldung das verständlich, mit dem Maximum.

### Behoben

- Hetzner: Der Traffic eines vSwitches zeigte „Hetzner Robot: Not Found“. Für vSwitch-Netze liefert die
  Robot-API keine Traffic-Werte. Die Seite sagt das jetzt, statt einen Fehler zu zeigen. Die vSwitch-Netze
  werden getrennt abgefragt, damit der Traffic der Server davon nie betroffen ist.

## 1.17.2 – 06.10.2026

### Behoben

- Updates: „Packages were downgraded and -y was used without --allow-downgrades“ ließ das ganze Update
  scheitern. Jetzt werden nur die betroffenen Pakete übersprungen, nicht heruntergestuft. Alle anderen
  Updates werden installiert, und das Protokoll nennt je Paket die Ursache (APT-Pinning oder Quelle der
  älteren Version).

## 1.17.1 – 06.10.2026

### Behoben

- easybell: „AMI: Zeitüberschreitung beim Lesen“.
  - Läuft die Ereignis-Verbindung, fragt der Servermanager Endgeräte und Gespräche jetzt über diese
    Verbindung ab, statt sich ein zweites Mal anzumelden. easybell erlaubt je Zugang nur eine
    AMI-Verbindung.
  - Zeilenenden ohne `\r` werden akzeptiert.
  - Bleibt die Begrüßung aus, nennt die Meldung die möglichen Ursachen: IP-Freigabe, AMI nicht
    aktiviert oder Zugang bereits verbunden.

## 1.17.0 – 06.10.2026

### Behoben

- Mailcow: „Weboberfläche und Mail-Hostname brauchen verschiedene Namen“ erschien auch, wenn die
  Weboberfläche gar nicht über Pangolin läuft. Ein gemeinsamer Name (z. B. `mail.example.com` für
  Weboberfläche und Mailserver auf der eigenen IP) ist jetzt erlaubt. Abgelehnt wird er nur, wenn der
  Name tatsächlich über Pangolin veröffentlicht ist. Der Optimierer schlägt die Veröffentlichung unter
  dem Mail-Namen nicht mehr vor, sondern empfiehlt zuerst einen eigenen Namen für die Weboberfläche.

### Neu

- **Proxmox VE per Klick an authentik (SSO):**
  - OpenID-Connect-Realm in Proxmox und passende Anwendung in authentik.
  - Benutzer werden beim ersten Login angelegt (ohne Rechte).
  - Optional werden authentik-Gruppen übernommen (ab PVE 8.1), und der Realm lässt sich als Standard
    vorwählen.
  - *Trennen* entfernt Realm und Anwendung.

  Details unter [Anwendungen](apps.md#sso-mit-authentik).

## 1.16.2 – 04.10.2026

### Verbessert

- Pangolin: Bei „Anmeldung fehlgeschlagen“ (HTTP 401) prüft der Servermanager, ob unter der Adresse
  überhaupt die Integration-API läuft (API-Dokumentation unter `…/v1/docs`). Die Meldung unterscheidet
  dann zwischen falschem Schlüssel, der internen Dashboard-API (`…/api/v1`) und einer anderen
  Gegenstelle, etwa einem vorgeschalteten Login. Sie nennt außerdem die verwendete Adresse und die
  Antwort des Servers.

## 1.16.1 – 04.10.2026

### Neu

- **Hetzner vSwitch:**
  - VLAN, angebundene Server mit Status und Warnung bei fehlgeschlagener Anbindung.
  - IP-Netze und Cloud-Netze.
  - PTR-Einträge in den vSwitch-Netzen.
  - Traffic der vSwitch-Netze.
  - Verknüpfung zum Proxmox-Server mit demselben VLAN; auf der Serverseite eine Übersicht der
    vSwitches.

### Behoben

- Hetzner Robot: Die Traffic-Abfrage scheiterte mit „Ungültige Eingabe (subnet)“, weil Subnetze mit
  Präfixlänge übergeben wurden. Ein einzelnes Subnetz, das Hetzner nicht auswertet, bricht die Abfrage
  nicht mehr ab.

## 1.16.0 – 04.10.2026

### Neu

- **Hetzner Cloud** neben den Root-Servern, mit mehreren Projekten:
  - Status, IP-Adressen und Floating-IPs mit PTR-Einträgen (auch IPv6), Traffic im
    Abrechnungszeitraum mit Warnung beim Inklusivvolumen.
  - CPU- und Netzwerk-Auslastung.
  - Neustart, Herunterfahren, Reset, Aus- und Einschalten sowie Umbenennen.
  - Rechte für ein ganzes Projekt oder einzelne Server mit den Stufen *Auswerten*, *Neustarten* und
    *Ändern*.

  Details unter [Hetzner](hetzner.md#cloud-server).

## 1.15.0 – 03.10.2026

### Neu

- **Hetzner Root-Server** über den Robot-Webservice, mit mehreren Konten:
  - Status und Traffic je Tag, Monat oder Jahr, mit Warnung beim Inklusivvolumen.
  - IP-Adressen mit PTR-Einträgen, auch für IPv6, PTR setzen und löschen.
  - Traffic-Warnungen, Neustarts (Software, Hardware, Ein-/Ausschalter, Techniker) und Wake-on-LAN.
  - Rechte für ein ganzes Konto oder einzelne Server mit den Stufen *Auswerten*, *Neustarten* und
    *Ändern*.

  Details unter [Hetzner Root-Server](hetzner.md).

## 1.14.0 – 02.10.2026

### Neu

- **easybell Cloud Telefonanlage** über die AMI-Schnittstelle: Endgeräte mit Status (optional mit
  Warnung), laufende Gespräche, Anrufjournal mit Suche und Filter sowie Anrufe in Zammad (CTI
  generisch). Die Anmeldung läuft per MD5-Challenge, das Passwort geht nie über die unverschlüsselte
  Verbindung. Details unter [easybell](easybell.md).

## 1.13.0 – 02.10.2026

### Neu

- **Anmeldung am Servermanager über authentik (SSO):** Einrichtung per Klick unter *SSO →
  Anwendungen*; Button „Mit authentik anmelden“ auf der Anmeldeseite. Zuordnung über den
  Benutzernamen, optional automatisches Anlegen (ohne Rechte) und Beschränkung auf eine
  authentik-Gruppe; Administratoren nur nach Freigabe; lokale Zwei-Faktor-Anmeldung bleibt wirksam.
  Details unter [Benutzer und Rechte](benutzer.md#anmeldung-uber-authentik-sso).

## 1.12.0 – 02.10.2026

### Neu

- **Pangolin per Klick an authentik (SSO):** Identity Provider in Pangolin, Anwendung in authentik mit
  der passenden Rückruf-Adresse, automatische Zuordnung neuer Benutzer zur Organisation. Trennen
  entfernt beides. Benötigt einen Server-Admin-API-Schlüssel in Pangolin.

### Behoben

- ISPConfig: Einrichten der Schnittstelle scheiterte mit „Funktionsgruppen der Remote-API nicht
  gefunden“, weil ISPConfig manche Funktionsgruppen mit Leerzeichen schreibt. PHP-Warnungen können das
  Ergebnis nicht mehr verfälschen.

## 1.11.2 – 02.10.2026

### Verbessert

- Wird eine Adresse ohne `http://` auf einem reinen http-Port eingetragen (z. B. authentik Port 9000),
  erklärt die Meldung jetzt die Ursache statt `[SSL: WRONG_VERSION_NUMBER]` – beim Abrufen des
  Fingerabdrucks und bei allen API-Verbindungen. Auch ein nicht passender Fingerabdruck wird erklärt.

## 1.11.1 – 30.09.2026

### Sicherheit

- Sicherheitsprüfung des gesamten Codes; 22 Lücken behoben (4 hoch, 5 mittel, 13 niedrig) – Details
  unter [Sicherheit](sicherheit.md).
- **Wichtig nach dem Update:**
  - WireGuard-MikroTik: unter *WireGuard → Einstellungen* einmal **Abrufen** (Fingerabdruck) und
    speichern – ohne gepinntes Zertifikat verbindet sich der Servermanager nicht mehr mit dem Router.
  - Neue Passwörter für Postfächer, SSO- und Nextcloud-Benutzer sowie SIP-Kennwörter erfordern jetzt
    Vollzugriff.
  - Abmelden beendet alle Sitzungen des Benutzers.
  - Das Update beschränkt die Größe von Anfragen ohne Anmeldung in der Anwendung selbst; die
    zusätzliche Grenze in nginx und die Rechte des privaten TLS-Schlüssels setzt das Update ebenfalls.

## 1.11.0 – 27.09.2026

### Neu

- **Zammad** direkt angebunden: Tickets aus Zabbix-Problemen werden in Zammad angelegt (Gruppe,
  Kunde, Priorität nach Schweregrad, Tags); Übernehmen, Kommentare, Schließen und Wiederöffnen werden
  übertragen; Schließen, Wiederöffnen und neue Notizen in Zammad kommen per signiertem Webhook zurück
  (Webhook und Trigger richtet der Servermanager in Zammad ein). Fehlgeschlagene Übergaben werden beim
  Abgleich nachgeholt.

## 1.10.0 – 26.09.2026

### Neu

- **ISPConfig** unter *Infrastruktur*: Kunden, Webseiten, E-Mail, DNS und Datenbanken über die
  Remote-API; Kunden und Postfächer anlegen, Postfach-Passwörter setzen, Webseiten (de)aktivieren.
- Die Schnittstelle wird **automatisch per SSH eingerichtet**, sobald ein System als ISPConfig erkannt
  wird: eigener Remote-Benutzer mit Zufallspasswort, nur den benötigten Funktionen und Beschränkung auf
  die Adresse des Servermanagers; Zertifikat wird gepinnt. Vorhandene Systeme per Klick.
- Die ISPConfig-Oberfläche wird in den Optimierungen zur Veröffentlichung über Pangolin vorgeschlagen.

## 1.9.0 – 26.09.2026

### Neu

- **Zabbix** unter *Infrastruktur*: Übersicht, Probleme, Hosts; *In Zabbix aufnehmen* installiert per
  SSH den Zabbix-Agent 2 mit eigenem PSK und legt den Host mit passenden Vorlagen an.
- **Tickets** aus Zabbix-Problemen: sofort per Webhook (Medientyp, Benutzer und Aktion richtet der
  Servermanager in Zabbix ein) und per Abgleich; übernehmen, kommentieren, zuweisen, schließen mit
  Rückmeldung an Zabbix; Weiterleitung an ein externes Ticketsystem per E-Mail; offene Tickets auf der
  System-Seite und als Zähler im Menü.

## 1.8.0 – 26.09.2026

### Neu

- **Telefonie (Asterisk/FreePBX)** unter *Infrastruktur*: Status, Gespräche, Trunk-Registrierungen,
  Nebenstellen mit Anmeldestatus; Nebenstellen anlegen, löschen und neue SIP-Passwörter setzen
  (FreePBX); Überwachung mit Warnungen bei gestopptem Asterisk und nicht registrierten Trunks.
- Systemmodul *Asterisk/FreePBX*: Neu laden, FreePBX-Module aktualisieren, Neustart; Modul-Updates in
  der Update-Übersicht.
- Optimierungen für Telefonanlagen: SIP-Helper (SIP-ALG) abschalten, SIP/RTP-Weiterleitung auf die
  Adressen des SIP-Providers beschränkt, optional eigene Public-IP; Prüfung von External Address,
  Local Networks und RTP-Bereich; Weboberfläche über Pangolin.

## 1.7.1 – 26.09.2026

### Verbessert

- Pangolin: Ein abgelehnter API-Schlüssel wird mit Ursachen gemeldet (Format `<ID>.<Geheimnis>`,
  Organisation, Server-Admin-Schlüssel); ein Schlüssel ohne ID-Teil wird direkt erkannt.

## 1.7.0 – 26.09.2026

### Neu

- Fortschrittsanzeige beim Update des Servermanagers: Schritte mit Häkchen, Fortschrittsbalken,
  Live-Protokoll, automatisches Wiederverbinden während des Neustarts, klare Erfolgs-/Fehlermeldung.
  Ein laufendes Update lässt sich über die Update-Seite wieder öffnen; ein zweiter Start ist gesperrt.

### Behoben

- Die Warteseite leitete nach 20 Sekunden weiter, auch wenn das Update noch lief.

## 1.6.3 – 26.09.2026

### Verbessert

- Updates installieren: Bei unterbrochenem dpkg oder fehlerhaften Abhängigkeiten repariert der
  Servermanager automatisch (`dpkg --configure -a` bzw. `apt-get -f install`) und versucht es erneut.
- Die Ursache eines fehlgeschlagenen Schritts (z. B. „Fehler beim Einrichten von: nginx“, „kein freier
  Speicherplatz“) steht jetzt in der Job-Zusammenfassung statt nur „Exit-Code 1“.

## 1.6.2 – 26.09.2026

### Verbessert

- Pangolin: Verbindungsfehler nennen die Ursache (Port 3003 nicht veröffentlicht, DNS, Zeitüberschreitung);
  die Hilfe beschreibt die Freigabe der Integration-API über Traefik.

## 1.6.1 – 26.09.2026

### Verbessert

- RouterOS-Ping-Test: Bei „Keine Antwort“ werden der Grund je Paket (z. B. Zeitüberschreitung, keine
  Route) und eine Diagnose angezeigt – fehlende/inaktive Default-Route (mit Hinweis für das Hetzner-Gateway
  172.31.1.1), Erreichbarkeit des Gateways, verwerfende Regeln in `chain=output` und Routing-Marken für
  Router-eigene Pakete.

## 1.6.0 – 26.09.2026

### Neu

- Fehlgeschlagenes Anlegen eines Containers lässt sich per **Wiederholen** im Job erneut ausführen; die
  Wiederholung setzt beim fehlgeschlagenen Schritt fort und legt nichts doppelt an.
- *Bestand übernehmen*: **Wiederholen** übernimmt nur die fehlgeschlagenen Gäste erneut; Gäste mit einem
  nicht erreichbaren System lassen sich wieder auswählen.
- System-Seite: **Einrichtung wiederholen** für Proxmox-Gäste (SSH-Schlüssel, Hostkeys, Prüfung).

### Geändert

- Die Übernahme eines Gastes gilt als fehlgeschlagen, wenn das System danach per SSH nicht erreichbar ist.

## 1.5.3 – 26.09.2026

### Verbessert

- RouterOS hinzufügen: Die Anmeldung wird vor dem Speichern geprüft; bei einem Fehler nennt die Meldung
  den Benutzer, die erkannte Absenderadresse und die typischen Ursachen (erlaubte Adresse, Rechte).
- Optional wird beim Hinzufügen direkt mit dem Admin-Zugang ein eigener API-Benutzer angelegt; nur
  dieser wird gespeichert. Passwörter mit Umlauten werden korrekt übertragen (UTF-8).

## 1.5.2 – 26.09.2026

### Behoben

- „Update konnte nicht gestartet werden: sm-helper self-update fehlgeschlagen“: Der Helfer wartete auf
  das Ende des gesamten Updates und wurde beim Neustart der Weboberfläche mit beendet. Update und
  Wiederherstellung werden jetzt ohne Warten gestartet (`systemd-run --no-block`); ein beim Neustart
  abgebrochener Aufruf gilt nicht mehr als Fehler. Fehlermeldungen des Helfers enthalten den Exit-Code.

## 1.5.1 – 26.09.2026

### Behoben

- Update-Prüfung schlug mit „couldn't find remote ref main“ fehl, wenn der eingestellte Branch im
  Repository nicht existiert. Jetzt gibt es eine verständliche Meldung und unter *Update → Update-Branch*
  die Auswahl der vorhandenen Branches.
- Das Installationsskript übernimmt ohne `--branch` den bisher eingestellten Branch bzw. den Branch des
  lokalen Checkouts und weicht auf den Standard-Branch des Repositorys aus, falls der Branch fehlt.
- Entwicklungsstand in den Branch `main` übernommen (Standard für Installation und Updates).

## 1.5.0 – 26.09.2026

### Neu

- **Nextcloud-Benutzer** per `occ`: anlegen (mit Gruppen, Quota, Zufallspasswort), sperren, neues
  Passwort, löschen.
- **Mailcow** über die API: Postfächer, Aliase, Domains, Überwachung. Weboberfläche über Pangolin,
  **IMAP/SMTP über eine eigene Public-IP**. Die Optimierungen richten auf dem RouterOS Mail-IP,
  Weiterleitung der Mail-Ports und Source-NAT für ausgehende Mails ein; die Mail-Ports gelten als
  erlaubte Ausnahme.
- **SSO mit authentik:** interne API, öffentliche Anmeldeseite über Pangolin, Benutzerverwaltung
  (optional mit Postfach). **Nextcloud (user_oidc) und Mailcow (Generic OIDC) per Klick verbinden**
  bzw. trennen, mit Rückbau bei Fehlern.
- Optimierungen: Weboberflächen von authentik, Mailcow und SSO-verbundenen Nextclouds über Pangolin
  veröffentlichen (ohne Pangolin-Anmeldung).

## 1.4.0 – 26.09.2026

### Neu

- **Domain-Zuordnung primär → Backup:** Für jede auf den primären Pangolin-Servern genutzte Domain wird
  beim Backup-Pangolin die Backup-Domain und eine Vorlage für die Subdomain festgelegt (`{sub}`,
  `{domain}`, `{base}`). Spiegeln, Übersicht und Optimierungen verwenden die Zuordnung, belegte Adressen
  werden erkannt, abweichende Backup-Wege markiert.

### Geändert

- Datenbank-Schema Version 4.

## 1.3.0 – 26.09.2026

### Neu

- **Bestand übernehmen:** vorhandene Container und VMs erhalten einen Management-Zugang (SSH-Schlüssel per
  `pct exec` bzw. QEMU-Guest-Agent, Hostkeys sicher übernommen) und werden als Systeme aufgenommen.
- **Management-Zugänge per einmaliger Admin-Anmeldung:** Proxmox-API-Token (auch mit 2FA-Code) und
  RouterOS-API-Benutzer mit zufälligem Passwort und Adressbeschränkung – Admin-Passwörter werden nicht
  gespeichert.
- RouterOS: Reiter **Geräte** (DHCP + ARP, Portfreigaben, zugehörige Systeme).
- **Optimierungen:** Scan über Proxmox, RouterOS und Pangolin mit Vorschlägen, Auswahl, Bestätigung und
  Umsetzung als Job – u. a. Portfreigaben durch Pangolin ersetzen (Ziel: eine Public-IP), Backup-Weg
  spiegeln, Autostart, Sicherungsjob, Disk, Guest-Agent, Leases statisch, Analyse-Ergebnisse des Routers.
- **Zwei Pangolin-Server** (primär/Backup-Weg) mit eigenem Tunnel-Container, Übersicht *Alle
  Veröffentlichungen* mit beiden Wegen, Failover-Hinweis in der Überwachung.
- **Newt-Tunnel-Container:** Einrichtung als systemd-Dienst (auch direkt beim Anlegen eines Containers),
  Modul mit Status, Neustart und Update; Prüfung, dass die Tunnel auf verschiedenen Proxmox-Hosts laufen
  (sonst Migrationsvorschlag).
- **Hetzner vSwitch:** Standort je Proxmox-Verbindung; Prüfung und Einrichtung der vSwitch-Bridge
  (VLAN, MTU 1400) je Node und der MTU der Gäste.

### Geändert

- Datenbank-Schema Version 3.

## 1.2.0 – 26.09.2026

### Neu

- **Proxmox VE über die API:** mehrere Server/Cluster mit API-Token (auch automatisch per SSH
  eingerichtet) und Zertifikats-Pinning; Container und VMs starten, herunterfahren, neu starten,
  stoppen, Snapshots, Sicherungen (vzdump), Ressourcen ändern, Disk vergrößern, löschen; Verlauf von
  CPU/RAM/Netz/Disk als Diagramme; Überwachung mit Warnungen (Node offline, Quorum, überwachter Gast
  läuft nicht, Disk/Storage voll).
- **Container anlegen** mit Vorlagen-Download, DHCP oder statischer IP, SSH-Schlüssel des
  Servermanagers; optional direkt als System aufnehmen, DHCP-Lease auf dem RouterOS statisch machen und
  über Pangolin veröffentlichen.
- Systeme lassen sich einem Proxmox-Gast zuordnen: Start/Stopp auf der System-Seite mit den Rechten des
  Systems.
- **RouterOS über die API** (mehrere Router, z. B. CHR): Übersicht, DHCP/Leases (statisch machen),
  NAT/Portweiterleitungen, Routing & Mangle, Firewall-Anzeige, DNS, Ping-Test.
- **Konfigurationsanalyse** für bestehende Router: Import per API oder `/export`, Soll-Ist-Vergleich
  (WAN, LAN/DHCP, DNS, NAT, Policy-Routing mit Mangle, FastTrack, MSS-Clamping, Firewall, Dienste),
  Anwenden unkritischer Änderungen mit vorheriger Sicherung, Skript für den Rest.
- **Pangolin:** Dienste mit Domain und Ziel (IP:Port) veröffentlichen, Ziele und Anmeldung verwalten,
  Überwachung der Newt-Sites.
- Rechte je API-Verbindung (Lesen/Bedienen/Vollzugriff) in der Benutzerverwaltung, Warnungen auf dem
  Dashboard und per E-Mail, neue Hilfeseiten.

### Geändert

- Datenbank-Schema Version 2 (wird beim Update automatisch migriert).

## 1.1.0 – 23.09.2026

### Neu

- Installation und Updates aus einem **privaten Repository** mit Lese-Token: `install.sh --token`
  (oder `SM_GIT_TOKEN`, bzw. verdeckte Abfrage), Ablage root-only in
  `/etc/servermanager/git-credentials`, automatische Verwendung durch `sm-update` und die
  Update-Prüfung.
- Menü **Update**: Token-Status anzeigen, neues Token prüfen und hinterlegen oder entfernen.

### Geändert

- Ein in der Repository-Adresse enthaltenes Token wird bei erneuter Installation in den
  Credential-Speicher verschoben.

## 1.0.0 – 23.09.2026

Erste Version.

### Neu

- Verwaltung von Debian 12/13, Nextcloud, Docker, ISPConfig und Proxmox VE über SSH (Schlüssel
  und/oder Passwort, sudo mit oder ohne Passwort, Hostkey-Prüfung).
- WireGuard-Management-Netz auf MikroTik (RouterOS 7): eigener Tunnel des Servermanagers,
  RouterOS-Einrichtungsbefehle, Peer-Übersicht.
- Enrollment per Skript: Geräte fordern ihren WireGuard-Zugang an, Peer/Route/Adressliste werden über
  die REST-API angelegt, SSH-Schlüssel und Hostkeys werden sicher übernommen.
- Direkte SSH-Verwaltung bestehender Systeme ohne Tunnel.
- Update-Übersicht über alle Geräte (Pakete, Sicherheitsupdates, Anwendungs-Updates,
  Release-Upgrade, Neustart).
- Wartungsplaner für zeitgesteuerte Updates und Wartungsarbeiten (einmalig, täglich, wöchentlich,
  monatlich; Wartungsfenster, Neustart-Regel, E-Mail-Bericht).
- Release-Upgrade Debian 12 → 13 mit Vorprüfung, Sicherung und automatischem Zurücksetzen der Quellen.
- Hintergrund-Jobs überstehen Verbindungsabbrüche und Neustarts des Servermanagers.
- Benutzer mit Rollen und Rechten je System, Zwei-Faktor-Anmeldung, Audit-Log.
- Backup/Restore des Servermanagers (optional verschlüsselt), Konfigurations-Backups der Systeme.
- Update des Servermanagers per Klick aus dem Git-Repository mit Rollback.
- Installationsskript für Debian 13 (LXC), nginx mit Let's Encrypt oder selbstsigniertem Zertifikat.
- Hilfe in der Weboberfläche.

### Sicherheit

- Adressen, Hostkeys und geroutete Netze können nur Administratoren ändern; Manager müssen beim
  Anlegen von Systemen einen Zugang nachweisen.
- Der Root-Helfer arbeitet nicht in Verzeichnissen des Dienstbenutzers und lehnt WireGuard-Hooks ab.
