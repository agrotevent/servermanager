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
