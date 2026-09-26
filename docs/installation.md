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

> Installiert und aktualisiert wird standardmäßig aus dem Branch `main`. Ein anderer Branch lässt sich
> mit `--branch NAME` wählen oder später in der Weboberfläche unter *Update → Update-Branch* umstellen.

### Installation aus einem privaten Repository (Token)

Für ein privates Repository wird ein **Zugriffstoken mit reinen Leserechten** benötigt:

- **GitHub:** *Settings → Developer settings → Personal access tokens → Fine-grained tokens*:
  *Repository access* nur auf `agrotevent/servermanager`, *Permissions → Contents: Read-only*
  (Metadata: Read-only wird automatisch gesetzt). Ablaufdatum nach Bedarf – vor Ablauf in der
  Weboberfläche ersetzen (siehe [Update des Servermanagers](servermanager-update.md)).
- **GitLab/Gitea:** Deploy- oder Projekt-Token mit `read_repository`; bei GitLab zusätzlich
  `--token-user oauth2` (Projekt-Token) bzw. den Namen des Deploy-Tokens angeben.

Installation ohne vorheriges `git clone` – nur das Installationsskript wird mit dem Token geladen:

```bash
TOKEN=github_pat_xxxxxxxx
BRANCH=main
apt-get update && apt-get install -y git curl
curl -fsSL -H "Authorization: Bearer $TOKEN" \
  "https://raw.githubusercontent.com/agrotevent/servermanager/$BRANCH/install.sh" -o install.sh
bash install.sh --token "$TOKEN" --branch "$BRANCH" --domain sm.example.com --email admin@example.com
```

Alternativ das Token als Umgebungsvariable übergeben (erscheint dann nicht in der Shell-History,
wenn es mit `read -s` eingelesen wird):

```bash
read -rs SM_GIT_TOKEN && export SM_GIT_TOKEN
bash install.sh --branch "$BRANCH" --domain sm.example.com
```

Wird kein Token angegeben und das Repository ist nicht öffentlich erreichbar, fragt das Skript im
interaktiven Betrieb verdeckt nach dem Token.

Was mit dem Token passiert:

- Es wird **nur für root lesbar** in `/etc/servermanager/git-credentials` (Rechte `600`) hinterlegt
  und im Checkout `/opt/servermanager` als Git-Credential-Speicher eingetragen.
- Das Update-Skript (`sm-update`) und die Update-Prüfung (`sm-helper git-fetch`) verwenden es
  automatisch – Updates per Klick funktionieren damit ohne weitere Eingabe.
- Es steht **nicht** in der Repository-Adresse, nicht in der Prozessliste und ist für den
  Dienstbenutzer `servermanager` (und damit für die Weboberfläche) nicht lesbar. Die Oberfläche zeigt
  nur die letzten vier Zeichen an.
- Eine bestehende Installation mit Token in der Repository-Adresse (`https://TOKEN@github.com/…`)
  wird beim erneuten Ausführen von `install.sh` automatisch umgestellt.
- Token ersetzen: Menü **Update → Zugriff auf das Repository** oder `bash install.sh --token NEU`.

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
| `--token TOKEN` | Lese-Token für ein privates Repository (auch `SM_GIT_TOKEN`); wird für Updates hinterlegt |
| `--token-user NAME` | Benutzername zum Token (Standard `x-access-token`, GitLab `oauth2`) |
| `--admin-user`, `--admin-password` | erster Administrator |
| `--listen 127.0.0.1:8000` | interne Adresse von gunicorn |
| `--timezone Europe/Berlin` | Zeitzone für Anzeige und Wartungsplaner |
| `--yes` | ohne Rückfragen |

Das Skript kann erneut ausgeführt werden (Reparatur/Aktualisierung); vorhandene Konfiguration,
Schlüssel und Daten bleiben erhalten.

Bei selbstsigniertem Zertifikat wird automatisch der **Zertifikats-Pin** hinterlegt – die
Enrollment-Befehle verwenden dann `curl --pinnedpubkey`, sodass auch ohne öffentliche CA eine sichere
Verbindung besteht.
