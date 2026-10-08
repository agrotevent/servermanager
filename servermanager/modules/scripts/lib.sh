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

# apt-get with automatic repair of the usual failures (interrupted dpkg, broken dependencies) and one
# retry. On failure APT_ERR holds a short reason for the error message.
APT_ERR=""
apt_try() {
    local out rc
    out="$(mktemp)"
    apt-get "$@" 2>&1 | tee "$out"
    rc=${PIPESTATUS[0]}
    APT_ERR=""
    if [ "$rc" -ne 0 ]; then
        APT_ERR="$(apt_reason "$out" | tr -s ' ' | sed 's/[; ]*$//')"
    fi
    APT_LAST_OUT="$(cat "$out")"
    rm -f "$out"
    return "$rc"
}

apt_reason() {
    local f="$1" pkgs
    if grep -q "No space left on device" "$f"; then
        echo "kein freier Speicherplatz ($(df -h / /var /boot 2>/dev/null | awk 'NR>1 {print $6 " " $4 " frei"}' | sort -u | tr '\n' ',' | sed 's/,$//'))"
    elif grep -qE "Could not get lock|Unable to acquire the dpkg frontend lock" "$f"; then
        echo "Paketverwaltung ist durch einen anderen Prozess gesperrt (läuft apt/unattended-upgrades?)"
    elif grep -q "Packages were downgraded" "$f"; then
        echo "apt würde Pakete auf ältere Versionen zurückstufen (APT-Pinning oder entfernte Paketquelle prüfen)"
    elif grep -q "dpkg was interrupted" "$f"; then
        echo "dpkg wurde unterbrochen (dpkg --configure -a nötig)"
    elif grep -qE "Unmet dependencies|unmet dependencies|held broken packages" "$f"; then
        echo "nicht erfüllte Abhängigkeiten: $(grep -E '^ [^ ].* : Depends:' "$f" | head -n 3 | sed 's/^ *//' | tr '\n' ';')"
    elif grep -q "Errors were encountered while processing:" "$f"; then
        pkgs="$(sed -n '/Errors were encountered while processing:/,$p' "$f" | sed -n 's/^ \{1,\}\([^ ].*\)$/\1/p' | head -n 5 | tr '\n' ' ')"
        echo "Fehler beim Einrichten von: ${pkgs:-?}"
    else
        grep -E '^(E:|dpkg: error|dpkg: Fehler)' "$f" | tail -n 2 | tr '\n' ' '
    fi
}

# packages the given apt-get command would DOWNGRADE, one "package installed offered" per line.
# The simulation allows downgrades: with -y apt would stop at the same error before listing anything.
apt_downgrades() {
    local p cur new
    LC_ALL=C apt-get -s "$@" --allow-downgrades 2>/dev/null \
        | sed -n 's/^Inst \([^ ]*\) \[\([^]]*\)\] (\([^ ]*\) .*/\1 \2 \3/p' \
        | while read -r p cur new; do
            if dpkg --compare-versions "$new" lt "$cur"; then
                printf '%s %s %s\n' "$p" "$cur" "$new"
            fi
        done
}

# why apt offers an older version: an APT pin naming the package, else priority and source of that version
apt_downgrade_cause() {
    local p="$1" new="$2" files src
    files="$(grep -lsE "^Package:.*(^|[ :*])${p}([ *]|\$)" /etc/apt/preferences /etc/apt/preferences.d/* 2>/dev/null \
             | tr '\n' ' ' | sed 's/ $//')"
    if [ -n "$files" ]; then
        printf 'APT-Pinning in %s' "$files"
        return
    fi
    src="$(LC_ALL=C apt-cache policy "$p" 2>/dev/null | awk -v v="$new" '
        ($1 == v) || ($1 == "***" && $2 == v) { prio = ($1 == "***") ? $3 : $2; found = 1; next }
        found && NF { print "Priorität " prio " aus " $2 " " $3; exit }')"
    printf '%s' "${src:-Quelle unbekannt}"
}

# apt refuses an upgrade because it would downgrade packages (pinning, removed repository):
# keep exactly those packages for this run, install everything else and say why they stay
apt_skip_downgrades() {
    local downs pkgs held p cur new rc
    downs="$(apt_downgrades "$@")"
    [ -n "$downs" ] || return 1
    held="$(apt-mark showhold 2>/dev/null | tr '\n' ' ')"
    pkgs=""
    while read -r p cur new; do
        warn "Nicht aktualisiert: $p – apt würde von $cur auf die ältere Version $new zurückstufen ($(apt_downgrade_cause "$p" "$new"))"
        case " $held " in *" $p "*) ;; *) pkgs="$pkgs $p" ;; esac
    done <<< "$downs"
    # shellcheck disable=SC2086 # word splitting of the package list is intended
    [ -z "$pkgs" ] || apt-mark hold $pkgs >/dev/null
    log "Übrige Updates ohne diese Pakete installieren"
    apt_try "$@"
    rc=$?
    # shellcheck disable=SC2086
    [ -z "$pkgs" ] || apt-mark unhold $pkgs >/dev/null
    APT_SKIPPED="$(printf '%s\n' "$downs" | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//')"
    return "$rc"
}

# shellcheck disable=SC2034 # read by the scripts that include this library
APT_SKIPPED=""
apt_run() {
    apt_try "$@" && return 0
    local reason="$APT_ERR"
    if printf '%s' "$APT_LAST_OUT" | grep -qE "Packages were downgraded and -y was used without --allow-downgrades"; then
        warn "apt würde Pakete auf ältere Versionen zurückstufen – diese werden übersprungen"
        apt_skip_downgrades "$@" && return 0
        [ -n "$APT_ERR" ] || APT_ERR="$reason"
        return 1
    elif printf '%s' "$APT_LAST_OUT" | grep -qE "dpkg was interrupted|Errors were encountered while processing:|Sub-process /usr/bin/dpkg returned an error"; then
        warn "Reparaturversuch: dpkg --configure -a"
        dpkg --configure -a --force-confdef --force-confold || true
    elif printf '%s' "$APT_LAST_OUT" | grep -qE "Unmet dependencies|unmet dependencies|apt --fix-broken install|-f install"; then
        warn "Reparaturversuch: apt-get -f install"
        apt-get "${APT_OPTS[@]}" -f install || true
    else
        APT_ERR="$reason"
        return 1
    fi
    log "Neuer Versuch nach der Reparatur"
    apt_try "$@" && return 0
    [ -n "$APT_ERR" ] || APT_ERR="$reason"
    return 1
}

# message for die(): "<what>: <reason>"
apt_fail() { die "$1${APT_ERR:+: $APT_ERR}"; }

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
