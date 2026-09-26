# shellcheck shell=bash
# Env: SM_MODE = upgrade | full-upgrade | security, SM_AUTOREMOVE = 0|1
stamp="$(mktemp)"
apt_update || die "apt-get update fehlgeschlagen"

mode="${SM_MODE:-upgrade}"
if is_proxmox && [ "$mode" = "upgrade" ]; then
    log "Proxmox VE erkannt - verwende 'dist-upgrade' (von Proxmox empfohlen)"
    mode="full-upgrade"
fi

case "$mode" in
    upgrade)
        log "Installiere Updates (apt-get upgrade --with-new-pkgs)"
        apt_run "${APT_OPTS[@]}" --with-new-pkgs upgrade || apt_fail "apt-get upgrade fehlgeschlagen"
        ;;
    full-upgrade)
        log "Installiere Updates (apt-get dist-upgrade)"
        apt_run "${APT_OPTS[@]}" dist-upgrade || apt_fail "apt-get dist-upgrade fehlgeschlagen"
        ;;
    security)
        pkgs="$(apt-get -s dist-upgrade 2>/dev/null | awk '/^Inst / && /[Ss]ecurity/ {print $2}' | sort -u | tr '\n' ' ')"
        if [ -z "$pkgs" ]; then
            log "Keine Sicherheitsupdates ausstehend."
        else
            log "Installiere Sicherheitsupdates: $pkgs"
            # shellcheck disable=SC2086
            apt_run "${APT_OPTS[@]}" install --only-upgrade $pkgs || apt_fail "Installation der Sicherheitsupdates fehlgeschlagen"
        fi
        ;;
    *) die "Unbekannter Modus $mode" ;;
esac

if [ "${SM_AUTOREMOVE:-1}" = "1" ]; then
    log "Nicht mehr benötigte Pakete entfernen (autoremove)"
    apt-get "${APT_OPTS[@]}" autoremove --purge || warn "autoremove fehlgeschlagen"
fi
apt-get -q clean || true
list_new_conffiles "$stamp"
rm -f "$stamp"
remaining="$(apt-get -s dist-upgrade 2>/dev/null | grep -c '^Inst ')"
log "Fertig. Noch ausstehende Paketupdates: $remaining"
report_reboot
exit 0
