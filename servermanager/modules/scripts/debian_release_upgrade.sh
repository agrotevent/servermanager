# shellcheck shell=bash
# Debian 12 (bookworm) -> Debian 13 (trixie) release upgrade.
# Env:
#   SM_CHECK_ONLY  1 = only run the pre-checks
#   SM_FORCE       1 = continue despite warnings from the pre-checks
#   SM_THIRD_PARTY keep    = switch third party repositories to trixie as well (default)
#                  disable = disable repositories that are not from debian.org during the upgrade
#   SM_MODERNIZE   1 = convert sources to deb822 format afterwards (apt modernize-sources)
FROM=bookworm
TO=trixie
export UCF_FORCE_CONFFOLD=1

# shellcheck disable=SC1091
. /etc/os-release
log "Aktuelles System: ${PRETTY_NAME:-unbekannt}"
[ "${ID:-}" = "debian" ] || die "Kein Debian-System (${ID:-?})."
if [ "${VERSION_ID:-}" = "13" ]; then
    log "Das System läuft bereits mit Debian 13 (trixie) - nichts zu tun."
    exit 0
fi
[ "${VERSION_ID:-}" = "12" ] || die "Das Upgrade wird nur von Debian 12 (bookworm) aus unterstützt (gefunden: ${VERSION_ID:-?})."
if is_proxmox; then
    die "Proxmox VE erkannt. Proxmox muss über den offiziellen Weg (pve8to9, Proxmox-Repositories) aktualisiert werden."
fi

# ---------------------------------------------------------------- checks
log "Vorprüfungen"
problems=0
arch="$(dpkg --print-architecture)"
case "$arch" in
    amd64|arm64|armhf|ppc64el|riscv64|s390x) echo "  Architektur: $arch - OK" ;;
    i386|armel) warn "Architektur $arch wird von Debian 13 nur noch eingeschränkt unterstützt."; problems=1 ;;
    *) warn "Architektur $arch wird von Debian 13 nicht mehr unterstützt."; problems=1 ;;
esac

avail_var="$(df -Pk /var/cache/apt/archives | awk 'NR==2{print $4}')"
avail_root="$(df -Pk / | awk 'NR==2{print $4}')"
avail_boot="$(df -Pk /boot | awk 'NR==2{print $4}')"
echo "  Freier Speicher: / $((avail_root / 1024)) MB, /var/cache/apt $((avail_var / 1024)) MB, /boot $((avail_boot / 1024)) MB"
if [ "${avail_var:-0}" -lt 2097152 ]; then warn "Weniger als 2 GB frei für heruntergeladene Pakete."; problems=1; fi
if [ "${avail_root:-0}" -lt 1048576 ]; then warn "Weniger als 1 GB frei auf /."; problems=1; fi
if [ "${avail_boot:-0}" -lt 102400 ]; then warn "Weniger als 100 MB frei auf /boot."; problems=1; fi

audit="$(dpkg --audit 2>&1)"
if [ -n "$audit" ]; then
    warn "dpkg meldet unvollständig installierte Pakete:"
    echo "$audit" | head -n 30
    problems=1
else
    echo "  dpkg-Status: OK"
fi
held="$(apt-mark showhold 2>/dev/null | tr '\n' ' ')"
if [ -n "$held" ]; then
    warn "Zurückgehaltene Pakete (können das Upgrade blockieren): $held"
fi

src_files=()
for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] && src_files+=("$f")
done
[ "${#src_files[@]}" -gt 0 ] || die "Keine APT-Quellen gefunden."
third=()
for f in "${src_files[@]}"; do
    if grep -vE '^\s*#' "$f" | grep -qE '(https?|mirror\+[a-z]+|file|cdrom):' \
        && ! grep -vE '^\s*#' "$f" | grep -qE 'debian\.org|debian-security|mirror\+|ftp\.[a-z.]*debian'; then
        third+=("$f")
    fi
done
if [ "${#third[@]}" -gt 0 ]; then
    warn "Quellen von Drittanbietern gefunden (müssen ein '$TO'-Repository anbieten):"
    printf '    %s\n' "${third[@]}"
fi
if ! grep -rqsE "\b$FROM\b" "${src_files[@]}"; then
    warn "In den APT-Quellen wurde '$FROM' nicht gefunden (evtl. 'stable' verwendet?)."
fi

if [ -f /usr/local/ispconfig/server/lib/config.inc.php ]; then
    iv="$(grep -oE "ISPC_APP_VERSION', *'[^']+" /usr/local/ispconfig/server/lib/config.inc.php | sed "s/.*'//")"
    warn "ISPConfig $iv ist installiert. Vor dem Upgrade prüfen, ob diese Version Debian 13 unterstützt, und ISPConfig anschließend aktualisieren (Dienste neu konfigurieren)."
fi
for occ in /var/www/nextcloud/occ /var/www/html/occ /var/www/*/occ; do
    [ -f "$occ" ] || continue
    ncv="$(grep -oE "OC_VersionString *= *'[^']+" "$(dirname "$occ")/version.php" 2>/dev/null | sed "s/.*'//")"
    warn "Nextcloud $ncv in $(dirname "$occ"): Debian 13 bringt PHP 8.4 mit - Nextcloud >= 31 wird benötigt, falls PHP aus Debian verwendet wird."
done
if command -v docker >/dev/null 2>&1; then
    echo "  Docker installiert: $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
fi

if [ "${SM_CHECK_ONLY:-0}" = "1" ]; then
    if [ "$problems" -eq 0 ]; then
        log "Vorprüfung erfolgreich - das System ist bereit für das Upgrade auf Debian 13."
        exit 0
    fi
    log "Vorprüfung mit Problemen abgeschlossen (siehe oben)."
    exit 2
fi
if [ "$problems" -ne 0 ] && [ "${SM_FORCE:-0}" != "1" ]; then
    die "Vorprüfung fehlgeschlagen - Upgrade abgebrochen. (Option 'Trotz Warnungen fortfahren' erzwingt das Upgrade.)"
fi

# ----------------------------------------------------- 1. update bookworm
stamp="$(mktemp)"
apt_update || die "apt-get update fehlgeschlagen"
log "Aktuelles Release vollständig aktualisieren"
apt-get "${APT_OPTS[@]}" dist-upgrade || die "Aktualisierung von Debian 12 fehlgeschlagen"

# ------------------------------------------------------ 2. backup sources
backup="/root/servermanager-apt-sources-$(date +%Y%m%d-%H%M%S).tar.gz"
log "Sicherung der APT-Quellen nach $backup"
tar czf "$backup" --ignore-failed-read -C / etc/apt/sources.list etc/apt/sources.list.d 2>/dev/null
[ -s "$backup" ] || die "Sicherung der APT-Quellen fehlgeschlagen"

disabled=()
restore_sources() {
    warn "Stelle ursprüngliche APT-Quellen wieder her"
    local f
    for f in "${disabled[@]}"; do
        [ -f "$f.disabled-by-servermanager" ] && mv -f "$f.disabled-by-servermanager" "$f"
    done
    tar xzf "$backup" -C /
    apt-get -q update >/dev/null 2>&1 || true
}

# ------------------------------------------------------ 3. switch sources
log "APT-Quellen auf '$TO' umstellen"
for f in "${src_files[@]}"; do
    is_third=0
    for t in "${third[@]}"; do [ "$t" = "$f" ] && is_third=1; done
    if [ "$is_third" = "1" ] && [ "${SM_THIRD_PARTY:-keep}" = "disable" ]; then
        mv -f "$f" "$f.disabled-by-servermanager"
        disabled+=("$f")
        echo "  deaktiviert: $f"
        continue
    fi
    sed -i -E "s/\b${FROM}\b/${TO}/g" "$f"
    echo "  umgestellt: $f"
done

# ------------------------------------------------------------ 4. update
log "Paketlisten für $TO laden"
if ! apt-get -q -o DPkg::Lock::Timeout=900 update; then
    restore_sources
    die "apt-get update mit den neuen Quellen fehlgeschlagen (fehlt ein Repository für '$TO'?). Die Quellen wurden zurückgesetzt - installiert wurden nur die Updates für Debian 12."
fi

# ----------------------------------------------------- 5. minimal upgrade
log "Minimales Upgrade (apt-get upgrade --without-new-pkgs)"
if ! apt-get "${APT_OPTS[@]}" upgrade --without-new-pkgs; then
    warn "Minimales Upgrade fehlgeschlagen - versuche Reparatur"
    dpkg --configure -a --force-confdef --force-confold || true
    apt-get "${APT_OPTS[@]}" -f install || die "Minimales Upgrade fehlgeschlagen - manueller Eingriff erforderlich (Quellen stehen auf $TO, Sicherung: $backup)"
fi

# -------------------------------------------------------- 6. full upgrade
log "Vollständiges Upgrade (apt-get full-upgrade)"
if ! apt-get "${APT_OPTS[@]}" full-upgrade; then
    warn "full-upgrade fehlgeschlagen - versuche Reparatur und zweiten Durchlauf"
    dpkg --configure -a --force-confdef --force-confold || true
    apt-get "${APT_OPTS[@]}" -f install || true
    apt-get "${APT_OPTS[@]}" full-upgrade || die "full-upgrade fehlgeschlagen - manueller Eingriff erforderlich (Sicherung der Quellen: $backup)"
fi

log "Nicht mehr benötigte Pakete entfernen"
apt-get "${APT_OPTS[@]}" autoremove --purge || warn "autoremove fehlgeschlagen"
apt-get -q clean || true

if [ "${SM_MODERNIZE:-0}" = "1" ]; then
    log "APT-Quellen in das deb822-Format umwandeln (apt modernize-sources)"
    apt -y modernize-sources || warn "apt modernize-sources fehlgeschlagen"
fi

if [ "${#disabled[@]}" -gt 0 ]; then
    warn "Folgende Drittanbieter-Quellen wurden deaktiviert und müssen manuell auf '$TO' umgestellt werden:"
    printf '    %s.disabled-by-servermanager\n' "${disabled[@]}"
fi
list_new_conffiles "$stamp"
rm -f "$stamp"

# shellcheck disable=SC1091
. /etc/os-release
log "Upgrade abgeschlossen: ${PRETTY_NAME}"
printf '\n[servermanager] Ein Neustart ist erforderlich, um den neuen Kernel zu laden.\n'
exit 0
