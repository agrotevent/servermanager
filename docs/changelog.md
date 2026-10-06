# Änderungsprotokoll

Alle wesentlichen Änderungen am Servermanager. Neue Einträge stehen oben.

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
