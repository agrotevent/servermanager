#!/bin/bash
# =============================================================================
#  Servermanager - Installation auf Debian 13 (trixie), z. B. im LXC-Container
#
#  Aufruf (als root):
#     bash install.sh                        # interaktiv
#     bash install.sh --domain sm.example.com --email admin@example.com --tls letsencrypt --yes
#
#  Optionen:
#     --domain FQDN          öffentlicher Name des Servermanagers
#     --email ADRESSE        E-Mail für Let's Encrypt / Admin
#     --tls MODUS            letsencrypt | selfsigned | none   (Standard: letsencrypt bei Domain, sonst selfsigned;
#                            none = ohne nginx/TLS, z. B. hinter einem vorhandenen Reverse-Proxy)
#     --repo URL             Git-Repository (Standard: https://github.com/agrotevent/servermanager.git)
#     --branch NAME          Branch für Installation und Updates (Standard: main)
#     --admin-user NAME      Name des ersten Administrators (Standard: admin)
#     --admin-password PW    Passwort (Standard: zufällig, wird angezeigt)
#     --listen ADRESSE       interne Adresse der Weboberfläche (Standard: 127.0.0.1:8000)
#     --timezone ZONE        Zeitzone für Anzeige/Wartungsplaner (Standard: Europe/Berlin)
#     --no-nginx             keinen nginx-Reverse-Proxy einrichten
#     --yes                  keine Rückfragen
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/agrotevent/servermanager.git"
BRANCH="main"
APP_DIR="/opt/servermanager"
DATA_DIR="/var/lib/servermanager"
CONF_DIR="/etc/servermanager"
SVC_USER="servermanager"
LISTEN="127.0.0.1:8000"
DOMAIN=""
EMAIL=""
TLS_MODE=""
ADMIN_USER="admin"
ADMIN_PASS=""
TIMEZONE="Europe/Berlin"
WITH_NGINX=1
ASSUME_YES=0

c_red() { printf '\033[31m%s\033[0m\n' "$*"; }
c_green() { printf '\033[32m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die() { c_red "FEHLER: $*" >&2; exit 1; }
ask() {  # ask "Frage" default -> REPLY
    local q="$1" def="${2:-}"
    if [ "$ASSUME_YES" = "1" ] || [ ! -t 0 ]; then REPLY="$def"; return; fi
    read -r -p "$q${def:+ [$def]}: " REPLY
    REPLY="${REPLY:-$def}"
}
confirm() {
    [ "$ASSUME_YES" = "1" ] && return 0
    [ -t 0 ] || return 0
    local a
    read -r -p "$1 [j/N] " a
    [[ "$a" =~ ^[jJyY] ]]
}

while [ $# -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="${2:-}"; shift ;;
        --email) EMAIL="${2:-}"; shift ;;
        --tls) TLS_MODE="${2:-}"; shift ;;
        --repo) REPO_URL="${2:-}"; shift ;;
        --branch) BRANCH="${2:-}"; shift ;;
        --admin-user) ADMIN_USER="${2:-}"; shift ;;
        --admin-password) ADMIN_PASS="${2:-}"; shift ;;
        --listen) LISTEN="${2:-}"; shift ;;
        --timezone) TIMEZONE="${2:-}"; shift ;;
        --no-nginx) WITH_NGINX=0 ;;
        --yes|-y) ASSUME_YES=1 ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) die "Unbekannte Option: $1 (--help für Hilfe)" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
step "Vorprüfungen"
[ "$(id -u)" = "0" ] || die "Bitte als root ausführen."
[ -r /etc/os-release ] || die "/etc/os-release fehlt"
# shellcheck disable=SC1091
. /etc/os-release
echo "System: ${PRETTY_NAME:-unbekannt}"
if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
    c_yellow "Hinweis: Getestet für Debian 13 (trixie). Gefunden: ${PRETTY_NAME:-?}"
    confirm "Trotzdem fortfahren?" || exit 1
fi
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Ungültiger Branch-Name"
LISTEN_RE='^[][0-9A-Za-z.:-]+:[0-9]+$'
[[ "$LISTEN" =~ $LISTEN_RE ]] || die "Ungültige Listen-Adresse"
[[ "$ADMIN_USER" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$ ]] || die "Ungültiger Admin-Benutzername"

VIRT="$(systemd-detect-virt 2>/dev/null || echo none)"
echo "Virtualisierung: $VIRT"

if [ -z "$DOMAIN" ]; then
    ask "Öffentlicher Domainname des Servermanagers (FQDN, leer = IP-Adresse)" "$(hostname -f 2>/dev/null || hostname)"
    DOMAIN="$REPLY"
fi
[[ -z "$DOMAIN" || "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "Ungültiger Domainname"
if [ -z "$TLS_MODE" ]; then
    if [[ "$DOMAIN" == *.* ]] && [[ ! "$DOMAIN" =~ ^[0-9.]+$ ]]; then
        ask "TLS-Zertifikat: letsencrypt oder selfsigned" "letsencrypt"
        TLS_MODE="$REPLY"
    else
        TLS_MODE="selfsigned"
    fi
fi
case "$TLS_MODE" in letsencrypt|selfsigned|none) ;; *) die "--tls muss letsencrypt, selfsigned oder none sein" ;; esac
if [ "$TLS_MODE" = "letsencrypt" ] && [ -z "$EMAIL" ]; then
    ask "E-Mail-Adresse für Let's Encrypt" ""
    EMAIL="$REPLY"
    [ -n "$EMAIL" ] || die "Für Let's Encrypt wird eine E-Mail-Adresse benötigt."
fi
[ "$TLS_MODE" = "none" ] && WITH_NGINX=0
[ "$WITH_NGINX" = "1" ] || TLS_MODE="none"

# ---------------------------------------------------------------------------
step "Pakete installieren"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q || c_yellow "Hinweis: apt-get update meldete Fehler (einzelne Paketquellen?) - fahre fort."
PKGS=(python3 python3-venv python3-dev git curl ca-certificates openssl sudo sqlite3 wireguard-tools
      iproute2 openssh-client tzdata build-essential libffi-dev)
[ "$WITH_NGINX" = "1" ] && PKGS+=(nginx)
[ "$TLS_MODE" = "letsencrypt" ] && PKGS+=(certbot)
apt-get install -y -q --no-install-recommends "${PKGS[@]}"

# ---------------------------------------------------------------------------
step "WireGuard-Unterstützung prüfen"
WG_OK=0
if ip link add dev smwgprobe type wireguard 2>/dev/null; then
    ip link del dev smwgprobe 2>/dev/null || true
    WG_OK=1
    c_green "WireGuard-Interfaces können angelegt werden."
else
    c_yellow "WireGuard-Interfaces können (noch) nicht angelegt werden."
    if [ "$VIRT" = "lxc" ]; then
        cat <<'HINT'
  Dieser Container läuft in LXC. Das WireGuard-Kernelmodul muss auf dem
  Proxmox-Host geladen sein. Auf dem Host ausführen:
      modprobe wireguard && echo wireguard >> /etc/modules-load.d/wireguard.conf
  Danach funktioniert WireGuard auch in unprivilegierten Containern.
  Die Installation wird fortgesetzt - der Tunnel kann später aktiviert werden.
HINT
    fi
fi

# ---------------------------------------------------------------------------
step "Dienstbenutzer und Verzeichnisse"
if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin --user-group "$SVC_USER"
fi
install -d -m 700 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"
for d in jobs backups system-backups ssh wireguard; do
    install -d -m 700 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR/$d"
done
install -d -m 750 -o root -g "$SVC_USER" "$CONF_DIR"

# ---------------------------------------------------------------------------
step "Programmcode ($APP_DIR)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"
git config --system --get-all safe.directory 2>/dev/null | grep -qx "$APP_DIR" \
    || git config --system --add safe.directory "$APP_DIR"
if [ -d "$APP_DIR/.git" ]; then
    echo "Vorhandene Installation gefunden - aktualisiere auf origin/$BRANCH"
    if git -C "$APP_DIR" fetch --quiet origin "$BRANCH"; then
        git -C "$APP_DIR" reset --quiet --hard "origin/$BRANCH"
    else
        c_yellow "origin/$BRANCH konnte nicht geholt werden - vorhandener Programmstand wird beibehalten."
    fi
elif [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/.git" ] && [ -f "$SCRIPT_DIR/servermanager/__init__.py" ] \
        && [ "$SCRIPT_DIR" != "$APP_DIR" ]; then
    echo "Installiere aus lokalem Checkout $SCRIPT_DIR"
    git clone --quiet --branch "$BRANCH" "$SCRIPT_DIR" "$APP_DIR" 2>/dev/null || git clone --quiet "$SCRIPT_DIR" "$APP_DIR"
    origin="$(git -C "$SCRIPT_DIR" config --get remote.origin.url || echo "$REPO_URL")"
    git -C "$APP_DIR" remote set-url origin "$origin"
    git -C "$APP_DIR" fetch --quiet origin "$BRANCH" 2>/dev/null || c_yellow "Hinweis: origin/$BRANCH nicht erreichbar - Updates prüfen!"
else
    git clone --quiet --branch "$BRANCH" "$REPO_URL" "$APP_DIR" || die "Repository $REPO_URL konnte nicht geklont werden"
fi
chown -R root:root "$APP_DIR"
chmod 755 "$APP_DIR"/bin/*

step "Python-Umgebung"
[ -x "$APP_DIR/.venv/bin/python" ] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
# make the package importable from any working directory
SITE="$("$APP_DIR/.venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
echo "$APP_DIR" > "$SITE/servermanager-app.pth"

# ---------------------------------------------------------------------------
step "Konfiguration ($CONF_DIR)"
if [ -n "$DOMAIN" ]; then
    BASE_URL="https://$DOMAIN"
    [ "$TLS_MODE" = "none" ] && BASE_URL="http://$DOMAIN"
else
    BASE_URL="http://$(hostname -I | awk '{print $1}')"
fi
SECURE="true"
[[ "$BASE_URL" == http://* ]] && SECURE="false"
CERT_FILE=""
[ "$TLS_MODE" = "selfsigned" ] && CERT_FILE="$CONF_DIR/tls/fullchain.pem"

if [ ! -f "$CONF_DIR/servermanager.conf" ]; then
    cat > "$CONF_DIR/servermanager.conf" <<EOF
# Servermanager - Grundkonfiguration (weitere Einstellungen in der Weboberfläche)
[server]
base_url = "$BASE_URL"
listen = "$LISTEN"
trusted_proxies = 1
secure_cookies = $SECURE
tls_cert_file = "$CERT_FILE"

[paths]
data_dir = "$DATA_DIR"
secret_key_file = "$CONF_DIR/secret.key"

[database]
url = "sqlite:///$DATA_DIR/servermanager.db"

[update]
repo_dir = "$APP_DIR"
branch = "$BRANCH"
helper = "$APP_DIR/bin/sm-helper"
use_sudo = true
EOF
else
    echo "Behalte vorhandene $CONF_DIR/servermanager.conf"
    LISTEN="$(sed -n 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$CONF_DIR/servermanager.conf" | head -n 1)"
    LISTEN="${LISTEN:-127.0.0.1:8000}"
fi
chown root:"$SVC_USER" "$CONF_DIR/servermanager.conf"
chmod 640 "$CONF_DIR/servermanager.conf"

if [ ! -f "$CONF_DIR/secret.key" ]; then
    umask 077
    head -c 32 /dev/urandom | base64 | tr '+/' '-_' > "$CONF_DIR/secret.key"
    umask 022
    echo "Hauptschlüssel erzeugt: $CONF_DIR/secret.key (in Backups enthalten - sicher aufbewahren!)"
fi
chown root:"$SVC_USER" "$CONF_DIR/secret.key"
chmod 640 "$CONF_DIR/secret.key"

cat > "$CONF_DIR/environment" <<EOF
SM_CONFIG=$CONF_DIR/servermanager.conf
SM_LISTEN=$LISTEN
PYTHONUNBUFFERED=1
EOF
chmod 644 "$CONF_DIR/environment"

# ---------------------------------------------------------------------------
step "sudo-Regel für den Hilfsdienst"
cat > /etc/sudoers.d/servermanager <<EOF
# Servermanager: der Dienstbenutzer darf ausschließlich den geprüften Helfer als root ausführen
Defaults:$SVC_USER !requiretty
$SVC_USER ALL=(root) NOPASSWD: $APP_DIR/bin/sm-helper
EOF
chmod 440 /etc/sudoers.d/servermanager
visudo -cf /etc/sudoers.d/servermanager >/dev/null || die "sudoers-Datei ungültig"

step "systemd-Dienste"
install -m 644 "$APP_DIR/deploy/servermanager-web.service" /etc/systemd/system/servermanager-web.service
install -m 644 "$APP_DIR/deploy/servermanager-worker.service" /etc/systemd/system/servermanager-worker.service
install -m 755 "$APP_DIR/bin/servermanager-cli" /usr/local/bin/servermanager-cli
systemctl daemon-reload

step "Datenbank und Administrator"
runcli() { runuser -u "$SVC_USER" -- env SM_CONFIG="$CONF_DIR/servermanager.conf" "$APP_DIR/.venv/bin/python" -m servermanager.cli "$@"; }
(cd "$APP_DIR" && runcli migrate)
(cd "$APP_DIR" && runcli set general.base_url "$BASE_URL" >/dev/null)
(cd "$APP_DIR" && runcli set general.timezone "$TIMEZONE" >/dev/null)
ADMIN_INFO=""
if ! (cd "$APP_DIR" && runcli users) | awk '{print $2}' | grep -qx admin; then
    if [ -n "$ADMIN_PASS" ]; then
        (cd "$APP_DIR" && runcli create-admin "$ADMIN_USER" --password "$ADMIN_PASS" --email "$EMAIL")
        ADMIN_INFO="Benutzer: $ADMIN_USER / Passwort: (wie angegeben)"
    else
        out="$(cd "$APP_DIR" && runcli create-admin "$ADMIN_USER" --generate --email "$EMAIL")"
        pw="$(echo "$out" | sed -n 's/^Initiales Passwort: //p')"
        ADMIN_INFO="Benutzer: $ADMIN_USER / Passwort: $pw   (muss bei der ersten Anmeldung geändert werden)"
    fi
else
    ADMIN_INFO="Vorhandene Administratoren bleiben unverändert (Passwort vergessen? servermanager-cli reset-password NAME)"
fi

# ---------------------------------------------------------------------------
if [ "$WITH_NGINX" = "1" ]; then
    step "nginx und TLS ($TLS_MODE)"
    install -d -m 750 -o root -g "$SVC_USER" "$CONF_DIR/tls"
    SERVER_NAME="${DOMAIN:-_}"
    CERT="$CONF_DIR/tls/fullchain.pem"
    KEY="$CONF_DIR/tls/privkey.pem"
    if [ ! -f "$CERT" ]; then
        SAN="DNS:${DOMAIN:-localhost}"
        for ip in $(hostname -I); do [[ "$ip" == *:* ]] || SAN="$SAN,IP:$ip"; done
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
            -subj "/CN=${DOMAIN:-servermanager}" -addext "subjectAltName=$SAN" \
            -keyout "$KEY" -out "$CERT" 2>/dev/null
        chmod 640 "$KEY"
        chown root:"$SVC_USER" "$KEY" "$CERT"
    fi
    sed -e "s|@DOMAIN@|$SERVER_NAME|g" -e "s|@CERT@|$CERT|g" -e "s|@KEY@|$KEY|g" -e "s|@LISTEN@|$LISTEN|g" \
        "$APP_DIR/deploy/nginx-servermanager.conf" > /etc/nginx/sites-available/servermanager
    # containers without IPv6: nginx would fail on "listen [::]:..."
    if [ ! -f /proc/net/if_inet6 ]; then
        sed -i '/listen \[::\]/d' /etc/nginx/sites-available/servermanager
    fi
    # nginx < 1.25.1 does not know "http2 on;" (e.g. Debian 12)
    NGX_VER="$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
    if [ -n "$NGX_VER" ] && [ "$(printf '%s\n1.25.1\n' "$NGX_VER" | sort -V | head -n 1)" != "1.25.1" ]; then
        sed -i -e '/http2 on;/d' -e 's/listen 443 ssl;/listen 443 ssl http2;/' -e 's/listen \[::\]:443 ssl;/listen [::]:443 ssl http2;/' \
            /etc/nginx/sites-available/servermanager
    fi
    ln -sf /etc/nginx/sites-available/servermanager /etc/nginx/sites-enabled/servermanager
    rm -f /etc/nginx/sites-enabled/default
    install -d /var/www/html
    nginx -t
    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx

    if [ "$TLS_MODE" = "letsencrypt" ]; then
        if certbot certonly --webroot -w /var/www/html -d "$DOMAIN" --email "$EMAIL" --agree-tos -n --keep-until-expiring; then
            LE="/etc/letsencrypt/live/$DOMAIN"
            sed -i -e "s|ssl_certificate .*|ssl_certificate     $LE/fullchain.pem;|" \
                   -e "s|ssl_certificate_key .*|ssl_certificate_key $LE/privkey.pem;|" /etc/nginx/sites-available/servermanager
            install -d /etc/letsencrypt/renewal-hooks/deploy
            printf '#!/bin/sh\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/servermanager-nginx
            chmod 755 /etc/letsencrypt/renewal-hooks/deploy/servermanager-nginx
            nginx -t && systemctl reload nginx
            c_green "Let's-Encrypt-Zertifikat eingerichtet (automatische Erneuerung über certbot.timer)."
        else
            c_yellow "Let's Encrypt fehlgeschlagen (DNS/Port 80 erreichbar?). Es wird das selbstsignierte Zertifikat verwendet."
            TLS_MODE="selfsigned"
        fi
    fi
    if [ "$TLS_MODE" = "selfsigned" ]; then
        PIN="$(openssl x509 -in "$CERT" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
        (cd "$APP_DIR" && runcli set enroll.tls_pin "$PIN" >/dev/null)
        sed -i "s|^tls_cert_file = .*|tls_cert_file = \"$CERT\"|" "$CONF_DIR/servermanager.conf"
        echo "Selbstsigniertes Zertifikat - Enrollment-Befehle verwenden den Zertifikats-Pin sha256//$PIN"
    fi
fi

# ---------------------------------------------------------------------------
step "Dienste starten"
systemctl enable servermanager-web servermanager-worker >/dev/null 2>&1
systemctl restart servermanager-web servermanager-worker
ok=0
for _ in $(seq 1 30); do
    if curl -fsS "http://$LISTEN/healthz" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
done
[ "$ok" = "1" ] || { journalctl -u servermanager-web -n 30 --no-pager; die "Weboberfläche startet nicht"; }

echo
c_green "=================================================================="
c_green " Servermanager wurde installiert."
c_green "=================================================================="
echo " Adresse:      $BASE_URL"
echo " $ADMIN_INFO"
echo
echo " Nächste Schritte:"
echo "  1. Anmelden und unter Profil die Zwei-Faktor-Anmeldung einrichten."
echo "  2. Menü 'WireGuard': MikroTik-Zugang und Management-Netz einrichten"
echo "     (RouterOS-Befehle werden dort erzeugt)."
[ "$WG_OK" = "1" ] || echo "     ACHTUNG: WireGuard ist in diesem Container noch nicht nutzbar (siehe Hinweis oben)."
echo "  3. Menü 'Enrollment': Token erzeugen und Befehl auf den Zielsystemen ausführen,"
echo "     oder bestehende Systeme unter 'Systeme' direkt per SSH hinzufügen."
echo
echo " Verwaltung:   servermanager-cli --help"
echo " Logs:         journalctl -u servermanager-web -u servermanager-worker -f"
echo
