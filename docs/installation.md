# Installation

Voraussetzungen:

- Debian 13 (trixie), z. B. als LXC-Container auf Proxmox (1 vCPU, 1 GB RAM, 8 GB Speicher genügen für
  viele Systeme)
- öffentlich erreichbarer Name (für Let's Encrypt Port 80/443 erreichbar) – alternativ selbstsigniertes
  Zertifikat
- für das Management-Netz: MikroTik mit RouterOS 7 (REST-API über den Dienst `www-ssl`)

**WireGuard im LXC-Container:** Das Kernelmodul muss auf dem Proxmox-**Host** geladen sein:

```bash
# auf dem Proxmox-Host
modprobe wireguard
echo wireguard > /etc/modules-load.d/wireguard.conf
```

Danach funktioniert WireGuard auch in unprivilegierten Containern.

### Installationsskript

```bash
apt-get update && apt-get install -y git
git clone https://github.com/agrotevent/servermanager.git /root/servermanager
cd /root/servermanager
bash install.sh --domain sm.example.com --email admin@example.com
```

> Solange die Entwicklung noch nicht in `main` übernommen ist, den Branch angeben:
> `git clone -b <branch> …` und `bash install.sh --branch <branch> …`

Das Skript

1. installiert Python, git, WireGuard-Tools, nginx, certbot, sudo,
2. prüft, ob WireGuard-Interfaces angelegt werden können (mit Hinweis für LXC),
3. legt den Dienstbenutzer `servermanager` an und installiert den Code nach `/opt/servermanager`
   (Python-venv unter `/opt/servermanager/.venv`),
4. erzeugt Konfiguration, Hauptschlüssel, SSH-Schlüssel und Datenbank,
5. richtet sudo-Regel, systemd-Dienste und nginx mit Let's Encrypt (oder selbstsigniert) ein,
6. legt den ersten Administrator an und zeigt das Initialpasswort an.

Optionen (`bash install.sh --help`):

| Option | Bedeutung |
|---|---|
| `--domain FQDN` | öffentlicher Name |
| `--email ADRESSE` | für Let's Encrypt |
| `--tls letsencrypt\|selfsigned\|none` | Zertifikat; `none` = ohne nginx (eigener Reverse-Proxy) |
| `--repo URL`, `--branch NAME` | Quelle für Installation **und** spätere Updates |
| `--admin-user`, `--admin-password` | erster Administrator |
| `--listen 127.0.0.1:8000` | interne Adresse von gunicorn |
| `--timezone Europe/Berlin` | Zeitzone für Anzeige und Wartungsplaner |
| `--yes` | ohne Rückfragen |

Das Skript kann erneut ausgeführt werden (Reparatur/Aktualisierung); vorhandene Konfiguration,
Schlüssel und Daten bleiben erhalten.

Bei selbstsigniertem Zertifikat wird automatisch der **Zertifikats-Pin** hinterlegt – die
Enrollment-Befehle verwenden dann `curl --pinnedpubkey`, sodass auch ohne öffentliche CA eine sichere
Verbindung besteht.
