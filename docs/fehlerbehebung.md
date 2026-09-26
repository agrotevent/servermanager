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
