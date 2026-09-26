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

## Update: „couldn't find remote ref main“

Der eingestellte Update-Branch existiert im Repository nicht. Unter *Update → Update-Branch* einen
vorhandenen Branch wählen. Alternativ als root:
`sed -i 's|^branch = .*|branch = "main"|' /etc/servermanager/servermanager.conf` und danach
`systemctl restart servermanager-web`.
