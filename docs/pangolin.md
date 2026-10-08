# Pangolin: Dienste veröffentlichen

[Pangolin](https://github.com/fosrl/pangolin) macht Dienste aus einem privaten Netz über einen Tunnel
unter einer öffentlichen Domain erreichbar. Im internen Netz läuft dafür ein **Newt**-Client (z. B. in
einem LXC hinter dem RouterOS), der sich ausgehend mit dem Pangolin-Server verbindet (*Site*).

Unter **Infrastruktur → Pangolin** trägt der Servermanager die nötige **Domain** und das **Ziel
(IP:Port)** im internen Netz über die Pangolin-API ein.

## Voraussetzungen

- Pangolin mit aktivierter Integration-API (`config.yml`):

  ```yaml
  flags:
    enable_integration_api: true
  ```

  Die API lauscht im Pangolin-Container auf Port **3003** – dieser Port ist **nicht** nach außen
  geöffnet (`https://<pangolin>:3003/v1` ergibt „Connection refused“). Sie wird über Traefik unter einer
  eigenen Subdomain veröffentlicht, z. B. in `config/traefik/dynamic_config.yml`:

  ```yaml
  http:
    routers:
      int-api-router-redirect:
        rule: "Host(`api.pangolin.example.com`)"
        service: int-api-service
        entryPoints: [web]
        middlewares: [redirect-to-https]
      int-api-router:
        rule: "Host(`api.pangolin.example.com`)"
        service: int-api-service
        entryPoints: [websecure]
        tls:
          certResolver: letsencrypt
    services:
      int-api-service:
        loadBalancer:
          servers:
            - url: "http://pangolin:3003"
  ```

  Dazu einen DNS-Eintrag für `api.pangolin.example.com` auf den Pangolin-Server setzen, Traefik neu
  starten (`docker compose restart traefik`) und im Servermanager **ohne Port** eintragen:
  `https://api.pangolin.example.com/v1`. Test: `curl https://api.pangolin.example.com/v1/` liefert
  eine JSON-Antwort.
- Ein **API-Schlüssel** der Organisation mit Rechten für Sites, Domains, Resources und Targets.
- Die **Organisations-ID** (steht in der Pangolin-URL: `/<org-id>/settings`).
- Eine Site mit Newt, die das interne Netz erreicht.

## Einrichten

**Pangolin hinzufügen** (nur Administratoren): API-Adresse, Organisations-ID, API-Schlüssel.
Bei einem Let’s-Encrypt-Zertifikat die CA-Prüfung aktiviert lassen, sonst den Fingerabdruck pinnen.
Nach dem Speichern können Standard-Site und -Domain gewählt werden.

## Dienst veröffentlichen

**Dienst veröffentlichen** (Vollzugriff):

| Feld | Bedeutung |
|---|---|
| Name | Anzeigename in Pangolin |
| Art | *HTTP(S) über Domain* (Standard) oder roher *TCP-/UDP-Port* |
| Subdomain + Domain | z. B. `cloud` + `example.com` → `cloud.example.com`; leer = Basisdomain |
| Site | der Newt-Client, über den das Ziel erreicht wird |
| IP-Adresse, Port | das Ziel im internen Netz, z. B. `10.20.0.50:80` |
| Ziel spricht | `http` oder `https` (wenn der Dienst selbst TLS spricht) |
| Pangolin-Anmeldung | SSO vorschalten (empfohlen) – ohne ist der Dienst für jeden erreichbar |

Schlägt das Anlegen des Ziels fehl, wird die gerade angelegte Resource wieder entfernt – es bleiben
keine halbfertigen Einträge zurück.

**Tipp:** Die Ziel-IP sollte sich nicht ändern. Bei DHCP die Lease auf dem RouterOS **statisch
machen** (Reiter *DHCP*) – beim Anlegen eines Containers über [Proxmox](proxmox.md) geht das
automatisch, ebenso die Veröffentlichung.

### DNS-Eintrag

Damit ein veröffentlichter Name erreichbar ist, braucht er einen DNS-Eintrag auf Pangolin. Ist ein
[DNS-Anbieter](dns.md) angebunden, legt der Servermanager diesen Eintrag beim Veröffentlichen
automatisch an:

- Ein CNAME auf das **DNS-Ziel veröffentlichter Namen** aus der Pangolin-Verbindung bzw. ein A/AAAA bei
  einer IP.
- Ist das Feld leer, zeigt der Eintrag auf die Adresse des Dashboards.
- Ein passender Platzhalter (`*.zone`) genügt, dann legt er nichts an.

## Verwalten

Die Detailseite zeigt die Sites (online/offline) und alle veröffentlichten Dienste mit Adresse,
Schutz (Anmeldung/öffentlich) und Status. Je Dienst:

- aktivieren/deaktivieren (Bedienen),
- Pangolin-Anmeldung ein-/ausschalten, Ziele hinzufügen/entfernen (mehrere Ziele = Lastverteilung),
  Veröffentlichung entfernen (Vollzugriff).

### Anmeldung über authentik (SSO)

Unter *Infrastruktur → SSO → (authentik) → Anwendungen → Pangolin verbinden* wird authentik per Klick
als Identity Provider in Pangolin eingerichtet – Details unter [Anwendungen](apps.md#sso-mit-authentik).
Dafür braucht die Pangolin-Verbindung einen Server-Admin-API-Schlüssel.

## Zwei Pangolin-Server: primärer und Backup-Weg

Es können mehrere Pangolin-Server eingebunden werden. Jeder bekommt eine **Rolle**:

- **Primär** – der normale Weg von außen.
- **Backup-Weg** – ein zweiter Pangolin-Server mit **eigenem Tunnel-Container (Newt)**, falls der primäre
  Server oder sein Tunnel ausfällt.

Einrichtung:

1. Beide Pangolin-Server hinzufügen, Rolle festlegen, je Standard-Site und -Domain wählen.
2. Je Server einen **Tunnel-Container** einrichten (siehe unten) – **auf verschiedenen Proxmox-Hosts**.
3. Beim Backup-Server die **Domain-Zuordnung** festlegen (siehe unten).
4. Dienste auf dem primären Server veröffentlichen und unter *Alle Veröffentlichungen* mit **Backup-Weg
   anlegen** zusätzlich über den Backup-Server veröffentlichen. Die [Optimierungen](bestand.md) schlagen
   das für alle Dienste ohne Backup-Weg vor.

### Domain-Zuordnung primär → Backup

Auf den primären Pangolin-Servern können mehrere Domains mit ihren Subdomains genutzt werden (z. B.
`example.com`, `firma.de`). Unter *Pangolin → Bearbeiten* des **Backup-Servers** wird für jede primäre
Domain festgelegt:

- **Backup-Domain:** eine der Domains des Backup-Pangolins. Mehrere primäre Domains können dieselbe
  Backup-Domain verwenden.
- **Vorlage** für die Subdomain mit den Platzhaltern `{sub}` (Subdomain auf dem primären Weg), `{domain}`
  (erster Teil der primären Domain) und `{base}` (primäre Domain, Punkte durch Bindestriche ersetzt).

| Primär | Backup-Domain | Vorlage | Backup-Adresse |
|---|---|---|---|
| `cloud.example.com` | `backup-example.net` | `{sub}` | `cloud.backup-example.net` |
| `cloud.firma.de` | `backup-example.net` | `{sub}-{domain}` | `cloud-firma.backup-example.net` |
| `firma.de` (Basisdomain) | `backup-example.net` | `{sub}-{domain}` | `firma.backup-example.net` |
| `shop.firma.de` | `firma-backup.de` | `{sub}` | `shop.firma-backup.de` |

Nutzen mehrere primäre Domains dieselbe Backup-Domain, braucht es eine unterscheidende Vorlage (z. B.
`{sub}-{domain}`). Sonst würden `cloud.example.com` und `cloud.firma.de` beide `cloud.backup-…` belegen.
Der Servermanager prüft vor dem Anlegen, ob die Adresse auf dem Backup-Server schon vergeben ist, und
bricht dann ab. Primäre Domains ohne Zuordnung verwenden die Standard-Domain des Backup-Servers mit der
unveränderten Subdomain. Die Übersicht zeigt die geplante Backup-Adresse vorab und markiert vorhandene
Backup-Wege, die von der Zuordnung abweichen.

*Alle Veröffentlichungen* zeigt je internem Ziel (IP:Port) beide Wege mit Domain, Schutz und Status.
Fällt der primäre Tunnel aus, meldet die Überwachung das zusammen mit dem Hinweis, ob der Backup-Weg
verfügbar ist.

> Ein automatisches Umschalten der primären Domain (DNS-Failover) gehört nicht zum Servermanager – im
> Störfall sind die Dienste über die Backup-Domain erreichbar.

## Tunnel-Container (Newt)

Der Newt-Client läuft am besten in einem eigenen kleinen Debian-LXC je Pangolin-Server:

- **Neu anlegen:** *Proxmox → Container anlegen* → Option **„Als Newt-Tunnel einrichten“**: Pangolin
  wählen, Endpoint (Adresse des Pangolin-Dashboards), Newt-ID und Secret (in Pangolin: *Sites → Site
  hinzufügen → Newt*) eingeben. Container, System, Newt-Dienst und Zuordnung entstehen in einem Job.
- **Vorhandenes System:** *Pangolin → Tunnel-Container einrichten*: installiert Newt als systemd-Dienst
  (`/usr/local/bin/newt`, Zugangsdaten root-only in `/etc/newt/newt.env`) und ordnet das System zu.
- Bestehende Newt-Installationen (systemd oder Docker-Container `fosrl/newt`) werden bei der
  Komponentenerkennung gefunden. Die Zuordnung erfolgt unter *Pangolin → Bearbeiten → Tunnel-Container*.

Auf der System-Seite zeigt der Reiter *Newt* Status, Version und letzte Meldungen, mit *Neu starten* und
*Aktualisieren*. Der Servermanager prüft, dass die Tunnel-Container der Pangolin-Server nicht auf
demselben Proxmox-Host laufen, und schlägt sonst eine Migration vor.

## Überwachung

Ist eine Site offline (Newt-Client nicht verbunden), meldet der Servermanager eine Warnung – alle
darüber veröffentlichten Dienste sind dann nicht erreichbar. Häufige Ursachen: Container gestoppt,
fehlender Internetzugang des LAN (NAT/Policy-Routing, siehe [RouterOS](routeros.md)).

## Kompatibilität

Die Integration-API hat sich zwischen Pangolin-Versionen leicht geändert (Resources gehörten früher zu
einer Site, neuere Versionen ordnen die Site dem Ziel zu). Der Servermanager unterstützt beide
Varianten automatisch.
