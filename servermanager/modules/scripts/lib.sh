# shellcheck shell=bash
# Common helpers for servermanager remote scripts.

log() { printf '\n==> [%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '\n[WARNUNG] %s\n' "$*"; }
die() { printf '\n[FEHLER] %s\n' "$*"; exit 1; }

export UCF_FORCE_CONFFOLD=1
# shellcheck disable=SC2034 # used by the scripts that include this library
APT_OPTS=(-y -q -o DPkg::Lock::Timeout=900 -o Dpkg::Options::=--force-confdef
          -o Dpkg::Options::=--force-confold -o APT::Get::Show-Upgraded=true)

apt_update() {
    log "Paketlisten aktualisieren (apt-get update)"
    local i
    for i in 1 2 3; do
        if apt-get -q -o DPkg::Lock::Timeout=900 update; then
            return 0
        fi
        warn "apt-get update fehlgeschlagen (Versuch $i/3)"
        sleep 10
    done
    return 1
}

is_proxmox() { command -v pveversion >/dev/null 2>&1; }

reboot_needed() {
    [ -f /var/run/reboot-required ] && return 0
    local running newest
    running="$(uname -r)"
    newest="$(find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null | sed 's/^vmlinuz-//' | sort -V | tail -n 1)"
    [ -n "$newest" ] && [ "$newest" != "$running" ] && return 0
    return 1
}

report_reboot() {
    if reboot_needed; then
        printf '\n[servermanager] Ein Neustart ist erforderlich, um alle Updates zu aktivieren.\n'
    fi
}

list_new_conffiles() {
    local since="$1" files
    files="$(find /etc \( -name '*.dpkg-dist' -o -name '*.dpkg-new' -o -name '*.ucf-dist' \) -newer "$since" 2>/dev/null)"
    if [ -n "$files" ]; then
        warn "Neue Paket-Konfigurationsdateien (alte Konfiguration wurde beibehalten, bitte prüfen):"
        printf '%s\n' "$files" | sed 's/^/    /'
    fi
}

valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9@._:+-]*$ ]]; }
