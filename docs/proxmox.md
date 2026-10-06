# Proxmox VE über die API

Unter **Infrastruktur → Proxmox** werden ein oder mehrere Proxmox-Server bzw. -Cluster über die
Proxmox-API angebunden. Damit lassen sich Container (LXC) und VMs **steuern, überwachen und
anlegen**, ohne dass der Servermanager auf dem Host per SSH arbeiten muss.

Die SSH-basierte Verwaltung des Proxmox-Hosts selbst (Paket-Updates, Upgrade-Prüfung, siehe
[Funktionen je Systemtyp](module.md)) bleibt davon unberührt – beides ergänzt sich.

## Verbindung einrichten

1. **Proxmox hinzufügen** (nur Administratoren): Name und API-Adresse, z. B.
   `https://10.66.0.11:8006`. Ein Cluster wird über einen beliebigen Node angebunden.
2. **Zertifikat:** Proxmox nutzt standardmäßig ein selbstsigniertes Zertifikat. Mit **Abrufen** wird
   der SHA-256-Fingerabdruck geholt und nach Vergleich festgeschrieben (Proxmox: *Node → System →
   Zertifikate*). Ändert sich das Zertifikat, schlägt die Verbindung fehl, statt einem fremden Server zu
   vertrauen. Alternativ: Prüfung über die System-CAs (z. B. bei Let’s-Encrypt-Zertifikat).
3. **API-Token:** Token-ID (`servermanager@pve!sm`) und Secret eintragen. Anlegen auf dem Host:

   ```bash
   pveum user add servermanager@pve
   pveum acl modify / --users servermanager@pve --roles PVEAdmin
   pveum user token add servermanager@pve sm --privsep 0
   ```

   **Automatisch:**
   - *Management-Zugang per Admin-Anmeldung* (Bearbeiten): einmalige Anmeldung, z. B. mit `root@pam`
     (optional mit 2FA-Code). Benutzer und Token werden über die API angelegt, das Passwort wird nicht
     gespeichert.
   - oder, wenn der Proxmox-Host bereits als System (SSH) im Servermanager ist: unter *Verknüpfungen*
     auswählen, speichern und **Token per SSH einrichten** klicken. Der Servermanager legt Benutzer und
     Token an, speichert das Secret verschlüsselt und pinnt das Host-Zertifikat.
   - **Standort:** *Lokal* (gemeinsames Netz) oder *Hetzner* mit der VLAN-ID des vSwitch (4000–4091).
     Die [Optimierungen](bestand.md) prüfen dann, ob jeder Node die vSwitch-Bridge (`vmbr<VLAN>`, MTU
     1400) hat und die Gäste darin MTU 1400 verwenden.
4. Optional: **RouterOS** (DHCP im Container-Netz) und **Pangolin** zuordnen – dann können neue
   Container ihre DHCP-Lease automatisch fixieren und direkt unter einer Domain veröffentlicht werden.

Die Rolle *PVEAdmin* genügt für alle Funktionen (inkl. Vorlagen-Download). Wer nur überwachen will,
kann eine Rolle mit weniger Rechten (z. B. *PVEAuditor*) vergeben – Aktionen schlagen dann mit
„Keine Berechtigung“ fehl.

## Übersicht und Überwachung

- **Liste:** Status, Nodes, laufende Container/VMs, CPU- und RAM-Auslastung, offene Warnungen.
- **Server-Seite:** Reiter *Container*, *VMs*, *Nodes & Storage*, *Jobs*; Start/Herunterfahren/Neustart
  direkt aus der Liste.
- **Gast-Seite:** Status, Ressourcen, Netzwerk, Verlaufsdiagramme (CPU, RAM, Netzwerk,
  Root-Dateisystem – Stunde bis Jahr, mit Tabellenansicht), Snapshots, Sicherungen, Jobs.

Der Worker fragt alle Verbindungen regelmäßig ab (*Einstellungen → Prüfungen & Jobs → API-Verbindungen
abfragen alle … Minuten*). Warnungen entstehen, wenn

- ein Node offline ist oder der Cluster kein Quorum hat,
- ein **überwachter** Gast nicht läuft (Button *Überwachen* auf der Gast-Seite; bei neu angelegten
  Containern voreingestellt),
- das Root-Dateisystem eines Containers oder ein Storage die Warnschwelle (Standard 90 %) erreicht,
- die API nicht erreichbar ist.

Neue und behobene Warnungen werden – wenn E-Mail eingerichtet ist – an die Administrator-Adressen
gemeldet und auf dem Dashboard der Verbindung angezeigt.

## Container und VMs steuern

| Aktion | Recht | Hinweis |
|---|---|---|
| Starten, Herunterfahren, Neustart, Hart stoppen | Bedienen | VMs zusätzlich Pausieren/Fortsetzen |
| Snapshot erstellen, Sicherung (vzdump) | Bedienen | Sicherung: Ziel-Storage und Modus wählbar |
| Snapshot zurückspielen/löschen | Vollzugriff | |
| CPU, RAM, Swap, Autostart, Beschreibung ändern | Vollzugriff | nur Container; wirkt sofort |
| Root-Disk vergrößern | Vollzugriff | nur Container, Verkleinern ist nicht möglich |
| Löschen | Vollzugriff | nur gestoppt, VMID zur Bestätigung |

Jede Aktion läuft als Job: das Protokoll des Proxmox-Tasks wird live angezeigt, ein Abbruch stoppt den
Task. Wird der Worker währenddessen neu gestartet (z. B. beim Update des Servermanagers), verfolgt er
den laufenden Task danach weiter, ohne ihn erneut auszulösen.

## Container anlegen

**Container anlegen** (Vollzugriff) auf der Server-Seite:

- **Node** wählen – Vorlagen, Storages, Bridges und Pools werden von diesem Node geladen.
- **Vorlage:** vorhandene Vorlagen oder direkt aus dem Proxmox-Katalog herunterladen (wird vor dem
  Anlegen automatisch geladen). Für Newt und typische Dienste: `debian-13-standard`.
- **Ressourcen:** Root-Storage und -Größe, Kerne, RAM, Swap; unprivilegiert und Nesting sind
  voreingestellt (für systemd in Debian 12/13 und Docker empfohlen).
- **Netzwerk:** Bridge, optional VLAN, IPv4 per **DHCP** (Adresse vom RouterOS) oder statisch, IPv6.
- **Anmeldung:** Root-Passwort und/oder SSH-Schlüssel; der Schlüssel des Servermanagers ist
  voreingestellt.
- **Integration:**
  - *Als System verwalten* – der Container wird nach dem Start mit seiner IP als System aufgenommen
    (Anmeldung als root per Servermanager-Schlüssel), Komponenten werden erkannt, Updates und
    Wartungsplaner stehen sofort zur Verfügung.
  - *DHCP-Lease statisch machen* – die vom RouterOS vergebene Adresse wird dem Container fest
    zugeordnet (Kommentar `servermanager: <hostname> (CT <vmid>)`).
  - *Über Pangolin veröffentlichen* – Subdomain, Domain, Site (Newt) und Port des Dienstes; der
    Servermanager legt Resource und Ziel in Pangolin an.

Ablauf des Jobs: Vorlage laden → Container anlegen → starten → auf die DHCP-Adresse warten → Lease
fixieren → als System aufnehmen → veröffentlichen. Das Root-Passwort wird nach dem Anlegen aus dem
Job entfernt.

### Fehlgeschlagen? Wiederholen

Bricht ein Schritt ab (z. B. keine DHCP-Adresse, Router oder Pangolin nicht erreichbar), zeigt der Job
den Knopf **Wiederholen**. Die Wiederholung ist ein neuer Job mit denselben Angaben, der **ab dem
fehlgeschlagenen Schritt** weitermacht – ein bereits angelegter Container wird nicht erneut angelegt,
ein laufender nicht erneut gestartet. Jeder Job lässt sich einmal wiederholen; schlägt auch die
Wiederholung fehl, hat sie wieder den Knopf. Wiederholen darf, wer Vollzugriff auf die
Proxmox-Verbindung hat (und Systeme anlegen darf, wenn der Container als System aufgenommen wird).

Ist der Container bereits als System aufgenommen, die Einrichtung aber unvollständig (z. B. SSH nicht
erreichbar), hilft auf der System-Seite im Kasten *Proxmox-Gast* **Einrichtung wiederholen**: SSH-Schlüssel
und Hostkeys werden über Proxmox erneut hinterlegt, ein fehlender SSH-Server installiert, die Adresse
bei Bedarf aktualisiert und das System geprüft.

## Bestand übernehmen

*Bestand übernehmen* listet alle Gäste mit IP, Bridge, Guest-Agent und Verwaltungsstatus. Ausgewählte
Gäste bekommen einen Management-Zugang (SSH-Schlüssel per `pct exec` bzw. Guest-Agent, Hostkey gepinnt)
und werden als Systeme aufgenommen – Details unter [Bestand übernehmen & Optimierungen](bestand.md).

Beim Anlegen eines Containers kann er zusätzlich **als Newt-Tunnel** für einen Pangolin-Server
eingerichtet werden (siehe [Pangolin](pangolin.md)).

## Verknüpfung mit Systemen

Ein System kann einem Proxmox-Gast zugeordnet werden (*System bearbeiten → Proxmox-Gast*, nur
Administratoren; bei „Als System verwalten“ automatisch). Auf der System-Seite erscheinen dann Status
und Start/Stopp des Gastes – nutzbar für alle Benutzer mit dem Recht **Bedienen auf dieses System**,
auch ohne Zugriff auf die Proxmox-Verbindung. So kann z. B. ein Kunde „seinen“ Container neu starten,
ohne die übrigen Gäste zu sehen.

## Anmeldung über authentik (SSO)

Unter *Infrastruktur → SSO → (authentik) → Anwendungen → Proxmox VE verbinden* wird authentik per Klick
als OpenID-Connect-Realm in Proxmox eingerichtet. Danach melden sich Benutzer mit ihrem authentik-Konto
an der Proxmox-Oberfläche an. Details stehen unter [Anwendungen](apps.md#sso-mit-authentik).

## Rechte

Administratoren haben Vollzugriff. Anderen Benutzern wird der Zugriff je Proxmox-Verbindung unter
**Benutzer → Infrastruktur** zugewiesen (Lesen / Bedienen / Vollzugriff, siehe [Benutzer und
Rechte](benutzer.md)). Verbindungen anlegen, ändern und Tokens einrichten dürfen nur Administratoren.
