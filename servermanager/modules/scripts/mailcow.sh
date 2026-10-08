# shellcheck shell=bash
# mailcow-dockerized: update check, update (update.sh), backup (helper-scripts/backup_and_restore.sh), status.
# Env: SM_TASK, SM_MC_PATH (installation, default /opt/mailcow-dockerized), SM_BACKUP (1 = back up first),
# SM_BACKUP_DIR (target of the backup)
MC="${SM_MC_PATH:-/opt/mailcow-dockerized}"
[ -f "$MC/mailcow.conf" ] && [ -f "$MC/update.sh" ] || die "Keine mailcow-Installation unter $MC (mailcow.conf/update.sh fehlen)"
cd "$MC" || die "$MC nicht lesbar"

mc_version() {
    local v
    v="$(sed -n 's/.*MAILCOW_GIT_VERSION="\([^"]*\)".*/\1/p' data/web/inc/app_info.inc.php 2>/dev/null | head -n 1)"
    [ -n "$v" ] || v="$(git -c safe.directory="$MC" describe --tags --abbrev=0 2>/dev/null)"
    echo "${v:-unbekannt}"
}

mc_compose() {
    if docker compose version >/dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi
}

mc_backup() {
    local dir="${SM_BACKUP_DIR:-/var/backups/mailcow}"
    [[ "$dir" =~ ^/[A-Za-z0-9._/-]{1,200}$ ]] || die "Ungültiger Sicherungsordner"
    mkdir -p "$dir" || die "Sicherungsordner $dir nicht anlegbar"
    log "Sicherung nach $dir (helper-scripts/backup_and_restore.sh backup all)"
    MAILCOW_BACKUP_LOCATION="$dir" ./helper-scripts/backup_and_restore.sh backup all \
        || die "Sicherung fehlgeschlagen – Update nicht gestartet"
    log "Sicherung fertig: $(du -sh "$dir" 2>/dev/null | cut -f1) in $dir"
}

# update.sh --check: exit code 0 = update available, 3 = none, 99 = GitHub not reachable; 2 = update.sh fetched
# newer _modules first and has to be started again
mc_check() {
    local rc out
    out="$(./update.sh --check 2>&1)"
    rc=$?
    if [ "$rc" -eq 2 ]; then
        out="$(./update.sh --check 2>&1)"
        rc=$?
    fi
    case "$rc" in
        0) echo "mailcow_update=yes" ;;
        3) echo "mailcow_update=no" ;;
        99) die "update.sh --check: GitHub nicht erreichbar" ;;
        *) printf '%s\n' "$out" | tail -n 5; die "update.sh --check fehlgeschlagen (Exit-Code $rc)" ;;
    esac
}

case "${SM_TASK:-}" in
    check)
        echo "mailcow_version=$(mc_version)"
        mc_check
        ;;
    status)
        echo "mailcow_version=$(mc_version)"
        echo "mailcow_branch=$(git -c safe.directory="$MC" rev-parse --abbrev-ref HEAD 2>/dev/null)"
        mc_compose ps --all --format '{{.Service}}|{{.State}}' 2>/dev/null | sed 's/^/container=/'
        ;;
    backup)
        mc_backup
        echo "SM_OK"
        ;;
    update)
        log "mailcow $(mc_version) unter $MC"
        [ "${SM_BACKUP:-0}" = "1" ] && mc_backup
        args=(--force)
        [ "${SM_SKIP_PING:-0}" = "1" ] && args+=(--skip-ping-check)
        log "Update ausführen (./update.sh ${args[*]}) – die Container werden neu gestartet"
        rc=0
        ./update.sh "${args[@]}" || rc=$?
        if [ "$rc" -eq 2 ]; then
            # update.sh fetched newer _modules of itself and asks to be started again
            log "update.sh hat seine Module aktualisiert – zweiter Durchlauf"
            rc=0
            ./update.sh "${args[@]}" || rc=$?
        fi
        [ "$rc" -eq 0 ] || die "update.sh fehlgeschlagen (Exit-Code $rc) – Ausgabe oben prüfen"
        log "Fertig: mailcow $(mc_version)"
        notrunning="$(mc_compose ps --all --format '{{.Service}}|{{.State}}' 2>/dev/null | grep -v '|running$' | cut -d'|' -f1 | tr '\n' ' ')"
        [ -z "$notrunning" ] || warn "Nicht laufende Container: $notrunning"
        echo "mailcow_version=$(mc_version)"
        echo "SM_OK"
        ;;
    *) die "Unbekannte Aufgabe ${SM_TASK:-}" ;;
esac
