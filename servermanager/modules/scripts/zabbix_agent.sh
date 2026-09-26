# shellcheck shell=bash
# Zabbix agent 2 with PSK encryption.
# Env: SM_ZBX_SERVER, SM_ZBX_HOSTNAME, SM_ZBX_PSK_ID, SM_ZBX_PSK, SM_ZBX_VERSION (e.g. 7.0)
ZDIR="${SM_ZBX_DIR:-/etc/zabbix}"
CONF="$ZDIR/zabbix_agent2.conf"
OWN="$ZDIR/servermanager-agent2.conf"
PSKF="$ZDIR/servermanager.psk"

[[ "${SM_ZBX_SERVER:-}" =~ ^[A-Za-z0-9.:,_-]+$ ]] || die "Ungültige Zabbix-Server-Adresse"
[[ "${SM_ZBX_HOSTNAME:-}" =~ ^[A-Za-z0-9._\ -]{1,128}$ ]] || die "Ungültiger Hostname"
[[ "${SM_ZBX_PSK_ID:-}" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || die "Ungültige PSK-Identität"
[[ "${SM_ZBX_PSK:-}" =~ ^[0-9a-f]{32,512}$ ]] || die "Ungültiger PSK"
ver="${SM_ZBX_VERSION:-7.0}"
[[ "$ver" =~ ^[0-9]+\.[0-9]+$ ]] || ver=7.0

if ! command -v zabbix_agent2 >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || die "Automatische Installation nur unter Debian/Ubuntu - zabbix-agent2 bitte manuell installieren"
    # shellcheck disable=SC1091
    . /etc/os-release
    export DEBIAN_FRONTEND=noninteractive
    installed=0
    case "${ID:-}" in
        debian|ubuntu)
            deb="zabbix-release_latest_${ver}+${ID}${VERSION_ID}_all.deb"
            tmp="$(mktemp -d)"
            for url in "https://repo.zabbix.com/zabbix/${ver}/${ID}/pool/main/z/zabbix-release/${deb}" \
                       "https://repo.zabbix.com/zabbix/${ver}/release/${ID}/pool/main/z/zabbix-release/${deb}"; do
                log "Zabbix-Paketquelle: $url"
                if command -v curl >/dev/null 2>&1 && curl -fsSL --retry 2 -o "$tmp/$deb" "$url"; then
                    if dpkg -i "$tmp/$deb" && apt_update && apt_run "${APT_OPTS[@]}" install zabbix-agent2; then
                        installed=1
                    fi
                    break
                fi
            done
            rm -rf "$tmp"
            ;;
    esac
    if [ "$installed" != 1 ]; then
        warn "Offizielle Zabbix-Paketquelle nicht nutzbar - verwende das Paket der Distribution"
        apt_update || die "apt-get update fehlgeschlagen"
        apt_run "${APT_OPTS[@]}" install zabbix-agent2 || apt_fail "Installation von zabbix-agent2 fehlgeschlagen"
    fi
fi
[ -f "$CONF" ] || die "$CONF nicht gefunden"

log "Agent konfigurieren (Server $SM_ZBX_SERVER, Host $SM_ZBX_HOSTNAME, PSK $SM_ZBX_PSK_ID)"
cp -n "$CONF" "$CONF.servermanager-orig" 2>/dev/null || true
# our values live in an own file - comment out the ones of the main configuration
sed -i -E 's/^(Server|ServerActive|Hostname|HostnameItem|TLSConnect|TLSAccept|TLSPSKIdentity|TLSPSKFile)=/# servermanager: &/' "$CONF"
grep -qxF "Include=$OWN" "$CONF" || printf '\n# Einstellungen des Servermanagers\nInclude=%s\n' "$OWN" >> "$CONF"
( umask 027; printf '%s\n' "$SM_ZBX_PSK" > "$PSKF" )
chown root:zabbix "$PSKF" 2>/dev/null || true
chmod 640 "$PSKF"
cat > "$OWN" <<CONFEOF
# verwaltet vom Servermanager
Server=$SM_ZBX_SERVER
ServerActive=$SM_ZBX_SERVER
Hostname=$SM_ZBX_HOSTNAME
TLSConnect=psk
TLSAccept=psk
TLSPSKIdentity=$SM_ZBX_PSK_ID
TLSPSKFile=$PSKF
CONFEOF
chmod 644 "$OWN"
if command -v docker >/dev/null 2>&1 && getent group docker >/dev/null; then
    usermod -aG docker zabbix 2>/dev/null && log "Benutzer zabbix zur Gruppe docker hinzugefügt (Docker-Überwachung)"
fi
systemctl enable zabbix-agent2 >/dev/null 2>&1 || true
systemctl restart zabbix-agent2 || { journalctl -u zabbix-agent2 -n 20 --no-pager 2>/dev/null; die "zabbix-agent2 startet nicht"; }
sleep "${SM_ZBX_WAIT:-2}"
systemctl is-active --quiet zabbix-agent2 || { journalctl -u zabbix-agent2 -n 20 --no-pager 2>/dev/null; die "zabbix-agent2 läuft nicht"; }
echo "SM_AGENT_VERSION=$(zabbix_agent2 -V 2>/dev/null | head -n 1)"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    warn "ufw ist aktiv - Port 10050/tcp muss vom Zabbix-Server erreichbar sein"
fi
echo "SM_OK"
