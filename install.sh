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
#     --branch NAME          Branch für Installation und Updates (Standard: vorhandene Einstellung bzw.
#                            Standard-Branch des Repositorys)
#     --token TOKEN          Zugriffstoken (nur Leserechte) für ein privates Repository; wird nach der
#                            Installation root-only in /etc/servermanager/git-credentials hinterlegt und
#                            von allen Updates verwendet (alternativ Umgebungsvariable SM_GIT_TOKEN)
#     --token-user NAME      Benutzername zum Token (Standard: x-access-token; GitLab: oauth2)
#     --admin-user NAME      Name des ersten Administrators (Standard: admin)
#     --admin-password PW    Passwort (Standard: zufällig, wird angezeigt; besser per Umgebungsvariable
#                            SM_ADMIN_PASSWORD übergeben – Argumente sind in der Prozessliste sichtbar)
#     --listen ADRESSE       interne Adresse der Weboberfläche (Standard: 127.0.0.1:8000)
#     --timezone ZONE        Zeitzone für Anzeige/Wartungsplaner (Standard: Europe/Berlin)
#     --no-nginx             keinen nginx-Reverse-Proxy einrichten
#     --yes                  keine Rückfragen
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/agrotevent/servermanager.git"
BRANCH="main"
BRANCH_SET=0
APP_DIR="/opt/servermanager"
DATA_DIR="/var/lib/servermanager"
CONF_DIR="/etc/servermanager"
SVC_USER="servermanager"
LISTEN="127.0.0.1:8000"
DOMAIN=""
EMAIL=""
TLS_MODE=""
ADMIN_USER="admin"
ADMIN_PASS="${SM_ADMIN_PASSWORD:-}"
TIMEZONE="Europe/Berlin"
WITH_NGINX=1
ASSUME_YES=0
GIT_TOKEN="${SM_GIT_TOKEN:-}"
GIT_USER="x-access-token"

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
        --branch) BRANCH="${2:-}"; BRANCH_SET=1; shift ;;
        --token) GIT_TOKEN="${2:-}"; shift ;;
        --token-user) GIT_USER="${2:-}"; shift ;;
        --admin-user) ADMIN_USER="${2:-}"; shift ;;
        --admin-password) ADMIN_PASS="${2:-}"; shift ;;   # alternativ: Umgebungsvariable SM_ADMIN_PASSWORD
        --listen) LISTEN="${2:-}"; shift ;;
        --timezone) TIMEZONE="${2:-}"; shift ;;
        --no-nginx) WITH_NGINX=0 ;;
        --yes|-y) ASSUME_YES=1 ;;
        -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
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
install -d -m 755 -o root -g root /var/log/servermanager

# ---------------------------------------------------------------------------
step "Programmcode ($APP_DIR)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"
git config --system --get-all safe.directory 2>/dev/null | grep -qx "$APP_DIR" \
    || git config --system --add safe.directory "$APP_DIR"
# never hang on a password prompt of git - a missing token is handled below
export GIT_TERMINAL_PROMPT=0

# Access token for a private repository: kept root-only in $CRED_FILE and used through
# git's credential store - it never appears in the remote URL, in the process list or in
# files the service user can read.
CRED_FILE="$CONF_DIR/git-credentials"
url_host() { sed -nE 's#^https://([^/@]*@)?([^/]+)/.*$#\2#p' <<<"$1"; }
url_strip_creds() { sed -E 's#^(https?://)[^/@]*@#\1#' <<<"$1"; }
take_url_creds() {  # move credentials embedded in an URL (https://user:token@host/...) into GIT_TOKEN
    local creds; creds="$(sed -nE 's#^https://([^/@]+)@.*$#\1#p' <<<"$1")"
    [ -n "$creds" ] || return 0
    if [[ "$creds" == *:* ]]; then
        [ -n "$GIT_TOKEN" ] || { GIT_TOKEN="${creds#*:}"; GIT_USER="${creds%%:*}"; }
    else
        [ -n "$GIT_TOKEN" ] || GIT_TOKEN="$creds"
    fi
}
valid_token() { [[ "$1" =~ ^[A-Za-z0-9_.~-]{8,255}$ ]]; }
write_git_credentials() {  # write_git_credentials URL
    local host; host="$(url_host "$1")"
    [ -n "$host" ] || die "Ein Token wird nur für https-Repositories unterstützt ($1)"
    valid_token "$GIT_TOKEN" || die "Ungültiges Token (erlaubt: A-Z a-z 0-9 _ . ~ -)"
    [[ "$GIT_USER" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || die "Ungültiger Token-Benutzer"
    ( umask 077; printf 'https://%s:%s@%s\n' "$GIT_USER" "$GIT_TOKEN" "$host" > "$CRED_FILE.tmp" )
    chown root:root "$CRED_FILE.tmp"
    chmod 600 "$CRED_FILE.tmp"
    mv -f "$CRED_FILE.tmp" "$CRED_FILE"
    echo "Zugriffstoken hinterlegt in $CRED_FILE (nur root lesbar)"
}
use_git_credentials() {  # configure the checkout to use the stored token for all fetches
    if [ -f "$CRED_FILE" ]; then
        git -C "$APP_DIR" config --replace-all credential.helper "store --file=$CRED_FILE"
    fi
}
git_cred() {  # git with the stored token (if any)
    if [ -f "$CRED_FILE" ]; then
        git -c credential.helper= -c "credential.helper=store --file=$CRED_FILE" "$@"
    else
        git "$@"
    fi
}
ask_token() {  # interactive fallback when the repository needs authentication
    [ -t 0 ] && [ "$ASSUME_YES" != "1" ] || return 1
    c_yellow "Das Repository ist nicht öffentlich erreichbar. Bitte ein Zugriffstoken mit Leserechten eingeben"
    c_yellow "(GitHub: Fine-grained Token, Repository-Zugriff nur auf dieses Repo, Contents: Read-only)."
    local t=""
    read -r -s -p "Token (leer = abbrechen): " t; echo
    [ -n "$t" ] || return 1
    GIT_TOKEN="$t"
}

remote_default_branch() {  # remote_default_branch URL
    git_cred ls-remote --symref "$1" HEAD 2>/dev/null \
        | sed -n 's#^ref: refs/heads/\([^[:space:]]*\)[[:space:]]*HEAD$#\1#p' | head -n 1
}
resolve_branch() {  # resolve_branch URL - use an existing branch (fallback: default branch of the repository)
    local url="$1" def
    [ -n "$url" ] || return 0
    if git_cred ls-remote --exit-code --heads "$url" "$BRANCH" >/dev/null 2>&1; then
        return 0
    fi
    def="$(remote_default_branch "$url")"
    if [ -n "$def" ] && [ "$def" != "$BRANCH" ]; then
        c_yellow "Branch '$BRANCH' gibt es im Repository nicht - verwende den Standard-Branch '$def'."
        BRANCH="$def"
    fi
}
if [ "$BRANCH_SET" = "0" ]; then
    if [ -f "$CONF_DIR/servermanager.conf" ]; then
        b="$(sed -n 's/^[[:space:]]*branch[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$CONF_DIR/servermanager.conf" | head -n 1)"
        [[ "$b" =~ ^[A-Za-z0-9._/-]+$ ]] && BRANCH="$b"
    elif [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/.git" ]; then
        b="$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
        [[ "$b" =~ ^[A-Za-z0-9._/-]+$ ]] && [ "$b" != "HEAD" ] && BRANCH="$b"
    fi
fi

take_url_creds "$REPO_URL"
REPO_URL="$(url_strip_creds "$REPO_URL")"
[ -n "$GIT_TOKEN" ] && write_git_credentials "$REPO_URL"

if [ -d "$APP_DIR/.git" ]; then
    echo "Vorhandene Installation gefunden - aktualisiere auf origin/$BRANCH"
    origin="$(git -C "$APP_DIR" config --get remote.origin.url || echo "$REPO_URL")"
    if [ "$origin" != "$(url_strip_creds "$origin")" ]; then
        # older installation with the token inside the remote URL: move it to the credential store
        take_url_creds "$origin"
        origin="$(url_strip_creds "$origin")"
        git -C "$APP_DIR" remote set-url origin "$origin"
        [ -n "$GIT_TOKEN" ] && write_git_credentials "$origin"
    elif [ -n "$GIT_TOKEN" ] && [ "$(url_host "$origin")" != "$(url_host "$REPO_URL")" ]; then
        write_git_credentials "$origin"
    fi
    use_git_credentials
    resolve_branch "$origin"
    if git -C "$APP_DIR" fetch --quiet origin "$BRANCH"; then
        git -C "$APP_DIR" reset --quiet --hard "origin/$BRANCH"
    else
        c_yellow "origin/$BRANCH konnte nicht geholt werden - vorhandener Programmstand wird beibehalten."
        [ -f "$CRED_FILE" ] || c_yellow "Privates Repository? Installation mit --token TOKEN wiederholen."
    fi
elif [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/.git" ] && [ -f "$SCRIPT_DIR/servermanager/__init__.py" ] \
        && [ "$SCRIPT_DIR" != "$APP_DIR" ]; then
    echo "Installiere aus lokalem Checkout $SCRIPT_DIR"
    git clone --quiet --branch "$BRANCH" "$SCRIPT_DIR" "$APP_DIR" 2>/dev/null || git clone --quiet "$SCRIPT_DIR" "$APP_DIR"
    origin="$(git -C "$SCRIPT_DIR" config --get remote.origin.url || echo "$REPO_URL")"
    case "$origin" in /*|file://*) origin="$REPO_URL" ;; esac
    if [ "$origin" != "$(url_strip_creds "$origin")" ]; then
        take_url_creds "$origin"
        origin="$(url_strip_creds "$origin")"
    fi
    git -C "$APP_DIR" remote set-url origin "$origin"
    if [ -n "$GIT_TOKEN" ] && { [ ! -f "$CRED_FILE" ] || [ "$(url_host "$origin")" != "$(url_host "$REPO_URL")" ]; }; then
        write_git_credentials "$origin"
    fi
    use_git_credentials
    resolve_branch "$origin"
    if ! git -C "$APP_DIR" fetch --quiet origin "$BRANCH" 2>/dev/null; then
        if [ ! -f "$CRED_FILE" ] && ask_token; then
            write_git_credentials "$origin"
            use_git_credentials
        fi
        git -C "$APP_DIR" fetch --quiet origin "$BRANCH" 2>/dev/null \
            || c_yellow "Hinweis: origin/$BRANCH nicht erreichbar - Updates prüfen (privates Repository: --token angeben)!"
    fi
else
    resolve_branch "$REPO_URL"
    if ! git_cred clone --quiet --branch "$BRANCH" "$REPO_URL" "$APP_DIR"; then
        rm -rf "$APP_DIR"
        if ask_token; then
            write_git_credentials "$REPO_URL"
            git_cred clone --quiet --branch "$BRANCH" "$REPO_URL" "$APP_DIR" \
                || { rm -rf "$APP_DIR"; die "Repository $REPO_URL konnte auch mit Token nicht geklont werden (Token-Rechte/Branch prüfen)"; }
        else
            die "Repository $REPO_URL konnte nicht geklont werden (privates Repository: --token TOKEN angeben)"
        fi
    fi
    use_git_credentials
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
    if ! grep -q "^branch = \"$BRANCH\"" "$CONF_DIR/servermanager.conf"; then
        sed -i "s|^branch = .*|branch = \"$BRANCH\"|" "$CONF_DIR/servermanager.conf"
        echo "Update-Branch auf '$BRANCH' gesetzt"
    fi
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
        # password via environment - never as a command line argument (visible in the process list)
        (cd "$APP_DIR" && export SM_ADMIN_PASSWORD="$ADMIN_PASS" \
            && runcli create-admin "$ADMIN_USER" --password-env SM_ADMIN_PASSWORD --email "$EMAIL")
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
        chown root:"$SVC_USER" "$CERT"
    fi
    # the private key is only needed by nginx (root) - not readable by the service user
    if [ -f "$KEY" ]; then chown root:root "$KEY"; chmod 600 "$KEY"; fi
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
if [ -f "$CRED_FILE" ]; then
    echo " Repository:   Zugriffstoken hinterlegt in $CRED_FILE (für Updates;"
    echo "               ändern unter Administration > Update oder erneut mit --token installieren)"
fi
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
