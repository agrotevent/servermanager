# Fehlerbehebung

| Problem | Lösung |
|---|---|
| „WireGuard-Interfaces können nicht angelegt werden“ im LXC | `modprobe wireguard` auf dem Proxmox-Host (siehe [Installation](installation.md)) |
| Dashboard meldet, der Worker antworte nicht | `systemctl status servermanager-worker`, `journalctl -u servermanager-worker` |
| Enrollment: „Servermanager nicht erreichbar“ | öffentliche URL unter *Einstellungen*, Firewall/Port 443, bei selbstsigniertem Zertifikat den Pin (Einstellungen → Enrollment) prüfen |
| Kein WireGuard-Handshake auf dem Client | Endpoint (UDP-Port) erreichbar? Firewall-Regel auf dem MikroTik vor `drop`-Regeln? |
| „Hostkey hat sich geändert“ | nach Neuinstallation eines Systems: System → Verwaltung → Hostkey zurücksetzen (sonst Angriff prüfen!) oder erneut per Enrollment-Token mit „Erneutes Enrollment“ |
| MikroTik-API: 401 | Benutzer, Passwort, `address=`-Einschränkung und Gruppe (`rest-api`, `read`, `write`) prüfen |
| Passwort vergessen | `servermanager-cli reset-password NAME` |

## Updates: „apt-get upgrade fehlgeschlagen“

Die eigentliche Ursache steht im Job-Protokoll direkt über der Meldung (Zeilen mit `E:` oder
`dpkg: error`). Ab 1.6.3 steht sie auch in der Zusammenfassung des Jobs. Der Servermanager repariert
zwei häufige Fälle selbst und versucht es dann noch einmal:

- **dpkg unterbrochen / Paket ließ sich nicht einrichten** → `dpkg --configure -a`
- **nicht erfüllte Abhängigkeiten** → `apt-get -f install`

Bleibt der Fehler, auf dem System als root prüfen:

- `dpkg --configure -a` und `apt-get -f install` von Hand – die Ausgabe zeigt das fehlerhafte Paket
  (oft ein Dienst, dessen Start im post-install-Skript scheitert, z. B. wegen einer fehlerhaften
  Konfiguration: `systemctl status <dienst>`, `journalctl -xeu <dienst>`).
- Speicherplatz: `df -h / /var /boot` (volles `/boot` bei Kernel-Updates).
- Sperre: läuft `unattended-upgrades` oder ein anderes `apt`? (`ps aux | grep -E 'apt|dpkg'`)
- Proxmox-Hosts ohne Subscription: das Enterprise-Repository deaktivieren bzw. das
  No-Subscription-Repository eintragen.

## „spricht kein TLS“ / `WRONG_VERSION_NUMBER`

Die Adresse wurde ohne `http://` eingetragen (dann wird https angenommen), der Port spricht aber nur
unverschlüsseltes http. Typisch bei **authentik**: Port **9000** ist http, Port **9443** ist https.
Richtig ist z. B. `https://10.200.30.99:9443` und dann den Fingerabdruck mit **Abrufen** pinnen.
Alternativ ausdrücklich `http://10.200.30.99:9000` – nur im internen Netz, weil das API-Token dann
unverschlüsselt übertragen wird.

## Pangolin: „Anmeldung fehlgeschlagen“

Unter der eingetragenen Adresse antwortet ein Server mit HTTP 401. Die Meldung nennt die verwendete
Adresse und die Antwort des Servers. Außerdem prüft der Servermanager selbst, ob dort überhaupt die
Integration-API läuft: Die hat unter `…/v1/docs` eine API-Dokumentation, die ohne Anmeldung erreichbar
ist.

- **„… ist die interne API des Pangolin-Dashboards“:** Eingetragen ist `https://<dashboard>/api/v1`.
  Diese API nimmt nur Browser-Sitzungen an. Die Integration-API hat eine eigene Adresse, z. B.
  `https://api.<domain>/v1` (intern Port 3003, Pfad `/v1`).
- **„… antwortet offenbar nicht die Integration-API“:** Unter der Adresse läuft etwas anderes, z. B.
  das Dashboard. Oder ein Login ist vorgeschaltet, etwa wenn die API selbst als Pangolin-Resource mit
  aktivierter Anmeldung veröffentlicht ist. Die Integration-API muss ohne Pangolin-Anmeldung erreichbar
  sein (in der Resource die Anmeldung ausschalten oder die API über Traefik direkt freigeben). Test im
  Browser: `https://api.<domain>/v1/docs` muss die API-Dokumentation zeigen.
- **„API-Schlüssel prüfen. Die Adresse stimmt“:** Die Integration-API ist erreichbar und lehnt den
  Schlüssel ab:

- **Schlüssel unvollständig:** Pangolin zeigt den Schlüssel nur einmal beim Anlegen an, im Format
  `<ID>.<Geheimnis>`. Beide Teile samt Punkt eintragen. Ist er nicht mehr bekannt, einen neuen anlegen.
- **Falsche Organisation:** Ein Schlüssel aus *Organisation → API-Schlüssel* gilt nur für diese
  Organisation. Die Organisations-ID im Servermanager muss dazu passen (steht in der Pangolin-URL
  `/<org-id>/settings`). Alternativ einen Server-Admin-Schlüssel verwenden.
- **Schlüssel gelöscht oder abgelaufen:** einen neuen anlegen, mit den Rechten für Sites, Domains,
  Resources und Targets.

Test auf dem Servermanager:
`curl -H "Authorization: Bearer <ID>.<Geheimnis>" https://api.<domain>/v1/org/<org-id>/sites`

## Pangolin: „Connection refused“ auf Port 3003

Port 3003 ist der interne Port der Integration-API im Docker-Netz von Pangolin und von außen nicht
erreichbar. Die API über Traefik unter einer eigenen Subdomain veröffentlichen und im Servermanager
ohne Port eintragen (`https://api.<domain>/v1`) – Anleitung unter [Pangolin](pangolin.md#voraussetzungen).
Außerdem muss in der `config.yml` `flags.enable_integration_api: true` gesetzt sein.

## RouterOS: Ping-Test „Keine Antwort von 1.1.1.1“

Der Router selbst erreicht das Ziel nicht. Bei einem Fehlschlag prüft der Servermanager automatisch und
nennt die wahrscheinliche Ursache:

- **Keine oder keine aktive Default-Route** in der Tabelle `main`. Bei Hetzner Cloud liegt das Gateway
  `172.31.1.1` außerhalb der /32-Adresse – die Route braucht das Interface:
  `/ip route add dst-address=0.0.0.0/0 gateway=172.31.1.1%ether1` (Interface anpassen). Bei einem
  DHCP-Client auf dem WAN-Interface `add-default-route=yes` prüfen.
- **Gateway antwortet nicht:** Anbindung/Provider prüfen (einige Gateways beantworten keinen Ping).
- **Gateway antwortet, Ziel nicht:** Filterregeln prüfen – Regeln in `chain=output` mit `drop`/`reject`
  betreffen Pakete des Routers selbst.
- **Mangle in `chain=output` mit `mark-routing`:** Pakete des Routers laufen dann über diese
  Routing-Tabelle, die eine funktionierende Default-Route braucht.
- Mit **Quelle** (LAN-Adresse) muss die Adresse auf dem Router existieren; ohne Antwort dann
  NAT (masquerade) und Policy-Routing der Konfigurationsanalyse prüfen.

Von Hand auf dem Router: `/ip route print where dst-address=0.0.0.0/0`, `/ping 1.1.1.1` und
`/ping <Gateway>`.

## RouterOS: „Anmeldung … fehlgeschlagen“

Der Router antwortet mit 401. Häufigste Ursachen:

- Die erlaubte Adresse des Benutzers (`/user print detail`, Feld `address`) enthält nicht die Adresse,
  mit der der Servermanager ankommt – z. B. anfangs dessen öffentliche IP statt des Management-Netzes.
  Beim Anlegen wird die erkannte Absenderadresse angezeigt.
- Falscher Benutzername oder falsches Passwort.
- Der Gruppe fehlen die Rechte `read`, `api` oder `rest-api`.

## Update: „couldn't find remote ref main“

Der eingestellte Update-Branch existiert im Repository nicht. Unter *Update → Update-Branch* einen
vorhandenen Branch wählen. Alternativ als root:
`sed -i 's|^branch = .*|branch = "main"|' /etc/servermanager/servermanager.conf` und danach
`systemctl restart servermanager-web`.

## Update: „sm-helper self-update fehlgeschlagen“

Betrifft Versionen bis 1.5.1: Das Update lief trotz der Meldung meist im Hintergrund weiter. Unter
*Update → Letztes Update-Protokoll* bzw. in `/var/log/servermanager/update.log` nachsehen. Ab 1.5.2 wird
das Update ohne Warten gestartet und die Meldung tritt nicht mehr auf. Hängt eine Installation auf einem
alten Stand fest, hilft einmalig als root: `/opt/servermanager/bin/sm-update`.
