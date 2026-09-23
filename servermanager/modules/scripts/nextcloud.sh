# shellcheck shell=bash
# Env: SM_TASK, SM_NC_PATH, SM_OCC (optional occ command override, e.g. for docker/snap)
NC="${SM_NC_PATH:-}"
PHP_OPTS=(-d apc.enable_cli=1 -d memory_limit=1G)
if [ -n "${SM_OCC:-}" ]; then
    occ() { bash -c "${SM_OCC} \"\$@\"" occ "$@"; }
    owner=""
else
    [ -n "$NC" ] && [ -f "$NC/occ" ] || die "Nextcloud nicht gefunden (Pfad: '${NC}'). Bitte Pfad in den System-Einstellungen hinterlegen."
    owner="$(stat -c %U "$NC/config/config.php" 2>/dev/null || stat -c %U "$NC/occ")"
    php_bin="$(command -v php)" || die "php-cli nicht gefunden"
    occ() { runuser -u "$owner" -- "$php_bin" "${PHP_OPTS[@]}" "$NC/occ" --no-ansi "$@"; }
fi

db_repair() {
    log "Datenbank: fehlende Indizes/Spalten/Primärschlüssel ergänzen"
    occ db:add-missing-indices --no-interaction || warn "db:add-missing-indices fehlgeschlagen"
    occ db:add-missing-columns --no-interaction || warn "db:add-missing-columns fehlgeschlagen"
    occ db:add-missing-primary-keys --no-interaction || warn "db:add-missing-primary-keys fehlgeschlagen"
}

case "${SM_TASK}" in
    check)
        echo "__STATUS__"
        occ status --output=json 2>/dev/null
        echo
        echo "__UPDATES__"
        occ update:check 2>&1
        ;;
    status)
        occ status
        log "Update-Prüfung"
        occ update:check
        ;;
    apps_update)
        log "Alle Apps aktualisieren"
        occ app:update --all || die "App-Update fehlgeschlagen"
        occ upgrade --no-interaction >/dev/null 2>&1 || true
        ;;
    maintenance_on)  occ maintenance:mode --on ;;
    maintenance_off) occ maintenance:mode --off ;;
    db_repair) db_repair ;;
    repair)
        log "occ maintenance:repair"
        occ maintenance:repair
        ;;
    repair_expensive)
        log "occ maintenance:repair --include-expensive (kann dauern)"
        occ maintenance:repair --include-expensive
        ;;
    files_scan)
        log "Dateien neu einlesen (occ files:scan --all)"
        occ files:scan --all
        ;;
    cron)
        [ -n "$owner" ] || die "Nur für klassische Installationen"
        log "Hintergrundjobs ausführen (cron.php)"
        runuser -u "$owner" -- "$php_bin" "${PHP_OPTS[@]}" -f "$NC/cron.php"
        ;;
    core_update)
        [ -z "${SM_OCC:-}" ] || die "Core-Update per Updater nur bei klassischen Installationen - bei Docker/Snap bitte das Image bzw. Snap aktualisieren."
        [ -f "$NC/updater/updater.phar" ] || die "updater.phar nicht gefunden"
        log "Aktueller Stand"
        occ status
        log "Nextcloud-Updater ausführen (updater.phar --no-interaction)"
        if ! runuser -u "$owner" -- "$php_bin" "${PHP_OPTS[@]}" "$NC/updater/updater.phar" --no-interaction; then
            warn "Updater meldete einen Fehler"
            occ status || true
            die "Nextcloud-Update fehlgeschlagen - bitte Log prüfen (Wartungsmodus ist evtl. noch aktiv)."
        fi
        log "occ upgrade"
        occ upgrade --no-interaction || warn "occ upgrade meldete einen Fehler"
        db_repair
        log "Wartungsmodus deaktivieren"
        occ maintenance:mode --off || true
        log "Neuer Stand"
        occ status
        occ update:check || true
        ;;
    *) die "Unbekannte Aufgabe ${SM_TASK}" ;;
esac
