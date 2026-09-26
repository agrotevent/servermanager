# shellcheck shell=bash
# Newt (Pangolin tunnel client). Env: SM_TASK, SM_NEWT_ID, SM_NEWT_SECRET, SM_NEWT_ENDPOINT
NEWT_BIN=/usr/local/bin/newt
NEWT_ENV=/etc/newt/newt.env
NEWT_UNIT=/etc/systemd/system/newt.service

newt_docker() { command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}} {{.Image}}' 2>/dev/null | awk '$2 ~ /fosrl\/newt/ {print $1; exit}'; }

download_newt() {
    local arch url
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        armv7l|armv6l) arch=arm32 ;;
        *) die "Nicht unterstützte Architektur $(uname -m)" ;;
    esac
    url="https://github.com/fosrl/newt/releases/latest/download/newt_linux_${arch}"
    if ! command -v curl >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get -q update >/dev/null && apt-get install -y -q curl ca-certificates >/dev/null
        fi
    fi
    log "Lade Newt herunter ($url)"
    curl -fsSL --retry 3 -o "$NEWT_BIN.new" "$url" || die "Download fehlgeschlagen"
    chmod 755 "$NEWT_BIN.new"
    "$NEWT_BIN.new" --version >/dev/null 2>&1 || "$NEWT_BIN.new" -h >/dev/null 2>&1 || die "Heruntergeladene Datei ist nicht ausführbar"
    mv -f "$NEWT_BIN.new" "$NEWT_BIN"
}

case "${SM_TASK:-status}" in
    setup)
        [ -n "${SM_NEWT_ID:-}" ] && [ -n "${SM_NEWT_SECRET:-}" ] && [ -n "${SM_NEWT_ENDPOINT:-}" ] || die "ID, Secret und Endpoint erforderlich"
        command -v systemctl >/dev/null 2>&1 || die "systemd wird benötigt"
        download_newt
        install -d -m 700 /etc/newt
        ( umask 077; printf 'NEWT_ID=%s\nNEWT_SECRET=%s\nPANGOLIN_ENDPOINT=%s\n' "$SM_NEWT_ID" "$SM_NEWT_SECRET" "$SM_NEWT_ENDPOINT" > "$NEWT_ENV" )
        cat > "$NEWT_UNIT" <<'UNIT'
[Unit]
Description=Newt - Pangolin tunnel client (servermanager)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/newt/newt.env
ExecStart=/usr/local/bin/newt
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable newt >/dev/null 2>&1
        systemctl restart newt
        sleep 5
        systemctl is-active --quiet newt || { journalctl -u newt -n 30 --no-pager; die "Newt startet nicht"; }
        log "Newt läuft ($("$NEWT_BIN" --version 2>/dev/null | head -n 1))"
        journalctl -u newt -n 10 --no-pager 2>/dev/null | sed -e 's/secret[^ ]*/secret=***/Ig'
        ;;
    restart)
        c="$(newt_docker)"
        if [ -f "$NEWT_UNIT" ] || systemctl list-unit-files newt.service >/dev/null 2>&1; then
            systemctl restart newt && sleep 3 && systemctl is-active newt
        elif [ -n "$c" ]; then
            docker restart "$c"
        else
            die "Kein Newt-Dienst gefunden"
        fi
        ;;
    update)
        [ -f "$NEWT_UNIT" ] || die "Update nur für die vom Servermanager eingerichtete Installation (systemd)"
        old="$("$NEWT_BIN" --version 2>/dev/null | head -n 1)"
        download_newt
        systemctl restart newt
        sleep 3
        systemctl is-active --quiet newt || die "Newt läuft nach dem Update nicht"
        log "Newt aktualisiert: ${old:-?} -> $("$NEWT_BIN" --version 2>/dev/null | head -n 1)"
        ;;
    status)
        c="$(newt_docker)"
        if [ -x "$NEWT_BIN" ] || command -v newt >/dev/null 2>&1; then
            echo "mode=systemd"
            echo "version=$( (newt --version 2>/dev/null || "$NEWT_BIN" --version 2>/dev/null) | head -n 1)"
            echo "active=$(systemctl is-active newt 2>/dev/null)"
            echo "since=$(systemctl show newt -p ActiveEnterTimestamp --value 2>/dev/null)"
            [ -f "$NEWT_ENV" ] && echo "endpoint=$(sed -n 's/^PANGOLIN_ENDPOINT=//p' "$NEWT_ENV")"
            journalctl -u newt -n 15 --no-pager -o cat 2>/dev/null | sed -e 's/secret[^ ]*/secret=***/Ig' | sed 's/^/log=/'
        elif [ -n "$c" ]; then
            echo "mode=docker"
            echo "version=$(docker inspect -f '{{.Config.Image}}' "$c" 2>/dev/null)"
            echo "active=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)"
            echo "since=$(docker inspect -f '{{.State.StartedAt}}' "$c" 2>/dev/null)"
            docker logs --tail 15 "$c" 2>&1 | sed -e 's/secret[^ ]*/secret=***/Ig' | sed 's/^/log=/'
        else
            echo "mode=none"
        fi
        ;;
    *) die "Unbekannte Aufgabe $SM_TASK" ;;
esac
