# Systeme hinzufügen

### Per Enrollment-Skript (empfohlen)

Menü **Enrollment** → Token erstellen (Einmal- oder Mehrfach-Token, Gültigkeit, Verbindungsart,
SSH-Benutzer, Systemtypen, geroutete Netze, Tags, Zugriffsrechte für Benutzer). Der angezeigte Befehl
wird auf dem neuen System als root ausgeführt:

```bash
curl -fsSL https://sm.example.com/enroll/<token>.sh | bash
# mit Optionen
curl -fsSL https://sm.example.com/enroll/<token>.sh | bash -s -- --name "Webserver 1"
```

| Option | Bedeutung |
|---|---|
| `--name NAME` | Anzeigename |
| `--direct` | ohne WireGuard, direkte SSH-Verbindung |
| `--address HOST` | Adresse für direkte Verbindungen – nur bei Tokens von Administratoren; sonst wird immer die Absenderadresse der Anfrage registriert |
| `--force` | vorhandene Tunnel-Konfiguration überschreiben |

Ablauf:

1. Das Skript installiert bei Bedarf `wireguard-tools`, erzeugt **lokal** ein WireGuard-Schlüsselpaar
   (der private Schlüssel verlässt das Gerät nie) und sendet Public Key, Hostname und die
   **SSH-Hostkeys** an den Servermanager.
2. Der Servermanager vergibt eine Management-IP, legt Peer/Route/Adressliste auf dem MikroTik an und
   antwortet mit der Tunnel-Konfiguration und seinem SSH-Public-Key.
3. Das Skript schreibt `/etc/wireguard/wg-mgmt.conf`, startet `wg-quick@wg-mgmt` und hinterlegt den
   SSH-Schlüssel – standardmäßig mit `from="<IP des Servermanagers>"`, der Schlüssel ist also nur aus dem
   Management-Netz nutzbar. Ist `PermitRootLogin no` gesetzt, wird automatisch der Benutzer `smadmin`
   mit sudo-Rechten verwendet.
4. Der Servermanager prüft die Verbindung (mit den übermittelten Hostkeys – kein „Trust on first use“),
   erkennt Docker, Nextcloud, ISPConfig und Proxmox und nimmt das System auf.

Proxmox-Hinweis: `/root/.ssh/authorized_keys` ist dort ein Link in das Cluster-Dateisystem – das Skript
schreibt in die Zieldatei und erhält den Link.

### Manuell per SSH (Bestandssysteme ohne Tunnel)

**Systeme → Manuell hinzufügen**: Host/IP, Port, Benutzer, Anmeldung per Servermanager-Schlüssel,
eigenem Schlüssel oder Passwort, sudo mit/ohne Passwort. Mit *SSH-Schlüssel automatisch installieren*
meldet sich der Servermanager einmal per Passwort an, hinterlegt seinen Schlüssel und stellt auf
Schlüssel-Anmeldung um. Der Hostkey wird beim ersten Verbindungsaufbau gespeichert und danach geprüft.
