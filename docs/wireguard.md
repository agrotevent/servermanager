# WireGuard-Management-Netz mit MikroTik

Menü **WireGuard**:

1. Einstellungen ausfüllen: Management-Netz (z. B. `10.66.0.0/24`), Adresse des MikroTik (`10.66.0.1`),
   Adresse des Servermanagers (`10.66.0.2`), öffentlicher Endpoint (`vpn.example.com:13231`),
   API-URL (`https://10.66.0.1`), API-Benutzer/Passwort.
2. Die angezeigten **RouterOS-Befehle** im MikroTik-Terminal ausführen. Sie legen an:
   - WireGuard-Interface `wg-mgmt` mit Adresse,
   - den Peer des Servermanagers (sein Public Key ist bereits eingesetzt),
   - Firewall-Regeln: WireGuard erlauben, REST-API nur vom Servermanager, Servermanager → Clients
     erlauben, **Clients untereinander isolieren**,
   - Zertifikat und `www-ssl` für die REST-API,
   - einen API-Benutzer mit eingeschränkten Rechten, der sich nur aus dem Tunnel anmelden darf.

   Firewall-Regeln ggf. vor vorhandene `drop`-Regeln verschieben und das Passwort anpassen.
3. Public Key des MikroTik eintragen (`/interface wireguard print`) und speichern.
4. **Tunnel aktivieren** – der Servermanager schreibt `/etc/wireguard/wg-sm.conf` und startet
   `wg-quick@wg-sm`.
5. **API testen** – übernimmt Version, Identität und den Public Key automatisch.

Die REST-API des MikroTik wird nur über **https mit geprüftem Zertifikat** angesprochen: Beim
selbstsignierten Zertifikat des Routers mit **Abrufen** den Fingerabdruck übernehmen (mit
`/certificate print detail` vergleichen) – er wird festgeschrieben. Ohne Fingerabdruck bzw.
CA-Prüfung verweigert der Servermanager die Verbindung, damit die Zugangsdaten nie an einen fremden
Server gehen. Bestehende Installationen: nach dem Update einmal *Abrufen* und speichern.

Beim Enrollment eines Geräts legt der Servermanager über die REST-API an:

| Objekt | Inhalt |
|---|---|
| WireGuard-Peer | Public Key des Geräts, `allowed-address` = Geräte-IP/32 (+ geroutete Netze), Kommentar `servermanager:<id>:<name>` |
| Adressliste | Eintrag in `servermanager-clients` (für eigene Firewall-Regeln) |
| Routen | für optionale Netze hinter dem Gerät (z. B. VM-Netz eines Proxmox-Hosts), Gateway `wg-mgmt` |

Der eigene Tunnel des Servermanagers erhält automatisch Routen für das Management-Netz und alle
gerouteten Netze. Die Tabelle *Peers auf dem MikroTik* zeigt Handshakes und Traffic, erkennt fehlende
und verwaiste Peers und kann sie neu anlegen bzw. entfernen.
