# shellcheck shell=bash
# Common helpers for servermanager remote scripts.

log() { printf '\n==> [%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '\n[WARNUNG] %s\n' "$*"; }
die() { printf '\n[FEHLER] %s\n' "$*"; exit 1; }

export UCF_FORCE_CONFFOLD=1
# shellcheck disable=SC2034 # used by the scripts that include this library
APT_OPTS=(-y -q -o DPkg::Lock::Timeout=900 -o Dpkg::Options::=--force-confdef
          -o Dpkg::Options::=--force-confold -o APT::Get::Show-Upgraded=true)

# apt-get update. Third-party sources often break on their own (rotated or expired signing key, mirror gone,
# no packages for this Debian release): known vendors' keys are renewed from their HTTPS address, sources that
# still fail are skipped for this run as long as the Debian sources themselves work.
APT_ETC="${SM_APT_ETC:-/etc/apt}"
APT_REPOS_SKIPPED=""
apt_update() {
    log "Paketlisten aktualisieren (apt-get update)"
    local i out rc keys_tried=0
    APT_REPOS_SKIPPED=""
    for i in 1 2 3; do
        out="$(mktemp)"
        LC_ALL=C apt-get -q -o DPkg::Lock::Timeout=900 update 2>&1 | tee "$out"
        rc=${PIPESTATUS[0]}
        if [ "$keys_tried" -eq 0 ] && grep -qE "$APT_KEY_ERRORS" "$out"; then
            keys_tried=1
            if apt_fix_repo_keys "$out"; then
                rm -f "$out"
                log "Neuer Versuch mit erneuerten Signaturschlüsseln"
                continue
            fi
        fi
        if [ "$rc" -eq 0 ]; then
            apt_report_failed_repos "$out"
            rm -f "$out"
            return 0
        fi
        if apt_only_foreign_failed "$out"; then
            apt_report_failed_repos "$out"
            warn "Diese Paketquellen werden für diesen Lauf übersprungen – Updates aus den übrigen Quellen werden installiert"
            rm -f "$out"
            return 0
        fi
        rm -f "$out"
        warn "apt-get update fehlgeschlagen (Versuch $i/3)"
        sleep "${SM_APT_RETRY_WAIT:-10}"
    done
    return 1
}

APT_KEY_ERRORS="NO_PUBKEY|Missing key|EXPKEYSIG|KEYEXPIRED|is not live|[Ee]xpired on|signing key .* is bad"

# failing sources of an apt-get update output, one "url suite<TAB>reason" per line. The last state of each
# file counts: apt retries, and a later "Hit" or "Get ... [size]" means the file did arrive after all.
apt_failed_repos() {
    awk '
        function flush() { if (cur != "") { reason[cur] = r; cur = "" } }
        /^(Hit|Get|Err|Ign):[0-9]+ / {
            flush()
            item = $2 " " $3 " " $4
            repo[item] = $2 " " $3
            if ($1 ~ /^Err:/) { state[item] = "err"; cur = item; r = "" }
            else if ($1 ~ /^Hit:/ || ($1 ~ /^Get:/ && $0 ~ /\]$/)) state[item] = "ok"
            next
        }
        cur != "" && /^  / { line = $0; sub(/^ +/, "", line); r = (r == "" ? line : r "; " line); next }
        { flush() }
        END {
            flush()
            for (i in state) if (state[i] == "err") print repo[i] "\t" reason[i]
        }
    ' "$1" | sort -u
}

apt_is_base_repo() {
    case "$1" in
        *://deb.debian.org/*|*://*.debian.org/*|*://debian.org/*|*://*.ubuntu.com/*) return 0 ;;
    esac
    return 1
}

# true if apt-get update only failed for third-party sources and fetched at least one source
apt_only_foreign_failed() {
    local f="$1" url _rest
    grep -qE '^(Hit|Get):[0-9]+ ' "$f" || return 1
    [ -n "$(apt_failed_repos "$f")" ] || return 1
    while IFS=' ' read -r url _rest; do
        apt_is_base_repo "$url/" && return 1
    done <<< "$(apt_failed_repos "$f")"
    return 0
}

# source files that name this repository URL
apt_source_files() {
    local hostpath="${1#*://}"
    grep -lsF "${hostpath%/}" "$APT_ETC/sources.list" "$APT_ETC"/sources.list.d/*.list "$APT_ETC"/sources.list.d/*.sources \
        2>/dev/null | tr '\n' ' ' | sed 's/ $//'
}

apt_repo_hint() {
    case "$1" in
        *"Missing key"*|*NO_PUBKEY*) echo "Signaturschlüssel fehlt (vom Anbieter erneuert?)" ;;
        *xpired*|*EXPKEYSIG*|*KEYEXPIRED*|*"is not live"*) echo "Signaturschlüssel abgelaufen" ;;
        *"401"*) echo "Zugang verweigert (401) – z. B. Enterprise-Quelle ohne Subskription" ;;
        *"404"*|*"does not have a Release file"*) echo "gibt es für diese Debian-Version nicht (404) – veraltete Quelle?" ;;
        *"Could not connect"*|*"timed out"*|*"Could not resolve"*|*"Temporary failure resolving"*|*"Unable to connect"*)
            echo "nicht erreichbar" ;;
        *) echo "${1:0:160}" ;;
    esac
}

apt_report_failed_repos() {
    local url_suite url suite reason files
    while IFS=$'\t' read -r url_suite reason; do
        [ -n "$url_suite" ] || continue
        url="${url_suite%% *}"
        suite="${url_suite#* }"
        files="$(apt_source_files "$url")"
        warn "Paketquelle übersprungen: $url $suite – $(apt_repo_hint "$reason")${files:+ (eingetragen in $files)}"
        APT_REPOS_SKIPPED="${APT_REPOS_SKIPPED:+$APT_REPOS_SKIPPED, }$url"
    done <<< "$(apt_failed_repos "$1")"
}

# official HTTPS address of the signing key of a known vendor repository
apt_vendor_key_url() {
    local url="${1%/}" seg
    case "$url" in
        *://nginx.org/*) echo "https://nginx.org/keys/nginx_signing.key" ;;
        *://packages.sury.org/*)
            seg="${url#*://packages.sury.org/}"
            seg="${seg%%/*}"
            [ -n "$seg" ] && echo "https://packages.sury.org/$seg/apt.gpg" ;;
        *://download.docker.com/linux/*)
            seg="${url#*://download.docker.com/linux/}"
            seg="${seg%%/*}"
            [ -n "$seg" ] && echo "https://download.docker.com/linux/$seg/gpg" ;;
    esac
}

# keyring file a source uses (signed-by in .list, Signed-By in .sources); empty: the global trusted.gpg.d
apt_signed_by() {
    local hostpath="${1#*://}" f path
    hostpath="${hostpath%/}"
    for f in "$APT_ETC/sources.list" "$APT_ETC"/sources.list.d/*.list; do
        [ -f "$f" ] || continue
        path="$(grep -F "$hostpath" "$f" | grep -E '^[[:space:]]*deb[[:space:]]' | sed -n 's/.*signed-by=\([^] ]*\).*/\1/p' | head -n 1)"
        [ -n "$path" ] && { echo "$path"; return; }
    done
    for f in "$APT_ETC"/sources.list.d/*.sources; do
        [ -f "$f" ] || continue
        path="$(awk -v u="$hostpath" 'BEGIN { RS = "" } index($0, u) {
                    n = split($0, lines, "\n")
                    for (i = 1; i <= n; i++) if (lines[i] ~ /^Signed-By:[ \t]*\//) { sub(/^Signed-By:[ \t]*/, "", lines[i]); print lines[i]; exit }
                }' "$f")"
        [ -n "$path" ] && { echo "$path"; return; }
    done
}

# ASCII-armored OpenPGP key(s) -> binary keyring, with gpg or without (base64 of each block)
apt_dearmor() {
    if command -v gpg >/dev/null 2>&1; then
        gpg --dearmor < "$1"
        return
    fi
    awk '/^-----BEGIN PGP PUBLIC KEY BLOCK-----/ { inb = 1; body = 0; next }
         /^-----END PGP PUBLIC KEY BLOCK-----/ { inb = 0; next }
         inb && !body { if ($0 ~ /^[ \t\r]*$/) body = 1; next }
         inb && body && /^=/ { next }
         inb && body { print }' "$1" | base64 -d
}

apt_fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-time 30 --proto '=https' -o "$2" "$1"
    else
        wget -q -T 30 -O "$2" "$1"
    fi
}

# renew the signing keys of known vendors whose sources failed with a key error; true if one was renewed
apt_fix_repo_keys() {
    local f="$1" url_suite url reason key_url keyring tmp bin fpr renewed=1 backup
    while IFS=$'\t' read -r url_suite reason; do
        url="${url_suite%% *}"
        printf '%s' "$reason" | grep -qE "$APT_KEY_ERRORS" || continue
        key_url="$(apt_vendor_key_url "$url")"
        [ -n "$key_url" ] || continue
        keyring="$(apt_signed_by "$url")"
        [ -n "$keyring" ] || keyring="$APT_ETC/trusted.gpg.d/servermanager-$(printf '%s' "${url#*://}" | cut -d/ -f1 | tr -c 'A-Za-z0-9.\n-' '_').gpg"
        log "Signaturschlüssel für $url vom Anbieter laden ($key_url)"
        tmp="$(mktemp)"
        bin="$(mktemp)"
        if ! apt_fetch "$key_url" "$tmp"; then
            warn "Schlüssel nicht ladbar: $key_url"
            rm -f "$tmp" "$bin"
            continue
        fi
        if grep -q "BEGIN PGP PUBLIC KEY BLOCK" "$tmp"; then
            apt_dearmor "$tmp" > "$bin" 2>/dev/null || :
        else
            cp "$tmp" "$bin"
        fi
        if [ ! -s "$bin" ]; then
            warn "Kein gültiger Schlüssel unter $key_url"
            rm -f "$tmp" "$bin"
            continue
        fi
        # apt names the key it needs only when one is missing; an expired key is replaced by the current one
        fpr="$(printf '%s' "$reason" | sed -n 's/.*Missing key \([0-9A-F]\{40\}\).*/\1/p' | head -n 1)"
        if [ -n "$fpr" ] && command -v gpg >/dev/null 2>&1 && \
           ! gpg --show-keys --with-colons "$bin" 2>/dev/null | grep -q ":$fpr:"; then
            warn "Der Schlüssel unter $key_url enthält $fpr nicht – nicht übernommen"
            rm -f "$tmp" "$bin"
            continue
        fi
        if [ -f "$keyring" ]; then
            backup="${SM_APT_KEY_BACKUP:-/var/backups/servermanager-apt-keys}"
            mkdir -p "$backup" 2>/dev/null && cp -p "$keyring" "$backup/$(basename "$keyring").$(date +%Y%m%d%H%M%S)" 2>/dev/null
        fi
        mkdir -p "$(dirname "$keyring")"
        install -m 0644 "$bin" "$keyring"
        log "Schlüssel erneuert: $keyring${fpr:+ (enthält $fpr)}"
        renewed=0
        rm -f "$tmp" "$bin"
    done <<< "$(apt_failed_repos "$f")"
    return "$renewed"
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

# the same from the output of the refused run itself ("The following packages will be DOWNGRADED:", with
# apt 3 also "DOWNGRADING:"): installed version from dpkg, offered one from the policy. Does not depend on a
# dry run, whose plan can differ (apt 3 solver).
apt_downgrades_from_output() {
    local p cur new
    printf '%s\n' "$1" | awk '
        /^The following packages will be DOWNGRADED:/ || /^DOWNGRADING:/ { inlist = 1; next }
        inlist && /^ / { for (i = 1; i <= NF; i++) if ($i ~ /^[a-z0-9][a-z0-9+.-]*(:[a-z0-9-]+)?$/) print $i; next }
        { inlist = 0 }' | sort -u | while read -r p; do
            cur="$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null)" || continue
            [ -n "$cur" ] || continue
            new="$(LC_ALL=C apt-cache policy "$p" 2>/dev/null | awk '$1 == "Candidate:" { print $2; exit }')"
            if [ -n "$new" ] && [ "$new" != "(none)" ] && dpkg --compare-versions "$new" lt "$cur"; then
                printf '%s %s %s\n' "$p" "$cur" "$new"
            fi
        done
}

# apt refuses an upgrade because it would downgrade packages (pinning, removed repository):
# keep exactly those packages for this run, install everything else and say why they stay
apt_skip_downgrades() {
    local downs pkgs held p cur new rc
    downs="$(apt_downgrades_from_output "$APT_LAST_OUT")"
    [ -n "$downs" ] || downs="$(apt_downgrades "$@")"
    if [ -z "$downs" ]; then
        warn "Die betroffenen Pakete ließen sich nicht bestimmen – Probelauf zur Fehlersuche:"
        LC_ALL=C apt-get -s "$@" --allow-downgrades 2>&1 | grep -E '^(Inst|Remv|E:|W:)' | head -n 30
        return 1
    fi
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
