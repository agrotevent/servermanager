# shellcheck shell=bash
# Env: SM_TASK, SM_SERVICE
case "${SM_TASK}" in
    autoremove)
        log "apt-get autoremove --purge"
        apt-get "${APT_OPTS[@]}" autoremove --purge
        ;;
    clean)
        log "apt-get clean / autoclean"
        apt-get -q clean && apt-get -q autoclean
        ;;
    fix_dpkg)
        log "dpkg --configure -a"
        dpkg --configure -a --force-confdef --force-confold || die "dpkg --configure -a fehlgeschlagen"
        log "apt-get -f install"
        apt-get "${APT_OPTS[@]}" -f install
        ;;
    journal_vacuum)
        log "Journal auf 14 Tage / 500M begrenzen"
        journalctl --vacuum-time=14d --vacuum-size=500M
        ;;
    restart_service)
        valid_name "${SM_SERVICE}" || die "Ungültiger Dienstname"
        log "Starte Dienst ${SM_SERVICE} neu"
        systemctl restart -- "${SM_SERVICE}" || die "Neustart fehlgeschlagen"
        systemctl --no-pager status -- "${SM_SERVICE}" | head -n 15
        ;;
    start_service|stop_service)
        valid_name "${SM_SERVICE}" || die "Ungültiger Dienstname"
        verb="${SM_TASK%_service}"
        log "systemctl ${verb} ${SM_SERVICE}"
        systemctl "$verb" -- "${SM_SERVICE}" || die "systemctl ${verb} fehlgeschlagen"
        ;;
    reset_failed)
        log "systemctl reset-failed"
        systemctl reset-failed
        ;;
    needrestart)
        if command -v needrestart >/dev/null 2>&1; then
            log "Dienste mit veralteten Bibliotheken neu starten (needrestart -r a)"
            needrestart -r a -b
        else
            log "needrestart ist nicht installiert - installiere es"
            apt-get "${APT_OPTS[@]}" install needrestart && needrestart -r a -b
        fi
        ;;
    *) die "Unbekannte Aufgabe ${SM_TASK}" ;;
esac
