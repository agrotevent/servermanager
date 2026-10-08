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
    # ---------------------------------------------------------------- users
    # Env: SM_UID, SM_DISPLAY, SM_EMAIL, SM_GROUPS (comma separated), SM_QUOTA, SM_NC_PASSWORD
    user_list)
        echo "__USERS__"
        occ user:list --info --output=json --limit=5000 2>/dev/null || occ user:list --output=json --limit=5000
        echo
        echo "__GROUPS__"
        occ group:list --output=json 2>/dev/null
        echo
        ;;
    user_add)
        [ -n "${SM_UID:-}" ] && [ -n "${SM_NC_PASSWORD:-}" ] || die "Benutzer-ID und Passwort erforderlich"
        args=(--password-from-env)
        [ -n "${SM_DISPLAY:-}" ] && args+=(--display-name="$SM_DISPLAY")
        IFS=',' read -r -a grps <<< "${SM_GROUPS:-}"
        for grp in "${grps[@]}"; do
            [ -n "$grp" ] || continue
            occ group:add "$grp" >/dev/null 2>&1 || true
            args+=(--group="$grp")
        done
        OC_PASS="$SM_NC_PASSWORD" occ user:add "${args[@]}" "$SM_UID" || die "Benutzer konnte nicht angelegt werden"
        [ -n "${SM_EMAIL:-}" ] && occ user:setting "$SM_UID" settings email "$SM_EMAIL"
        [ -n "${SM_QUOTA:-}" ] && occ user:setting "$SM_UID" files quota "$SM_QUOTA"
        echo "SM_OK"
        ;;
    user_disable) occ user:disable "$SM_UID" && echo "SM_OK" ;;
    user_enable)  occ user:enable "$SM_UID" && echo "SM_OK" ;;
    user_delete)  occ user:delete "$SM_UID" && echo "SM_OK" ;;
    user_resetpw)
        [ -n "${SM_NC_PASSWORD:-}" ] || die "Passwort erforderlich"
        OC_PASS="$SM_NC_PASSWORD" occ user:resetpassword --password-from-env "$SM_UID" && echo "SM_OK"
        ;;
    user_quota)   occ user:setting "$SM_UID" files quota "$SM_QUOTA" && echo "SM_OK" ;;
    # ---------------------------------------------------------------- SSO (app user_oidc)
    # Env: SM_OIDC_ID, SM_OIDC_CLIENT, SM_OIDC_SECRET, SM_OIDC_DISCOVERY
    url)
        echo "url=$(occ config:system:get overwrite.cli.url 2>/dev/null)"
        echo "domains=$(occ config:system:get trusted_domains 2>/dev/null | tr '\n' ' ')"
        ;;
    oidc_setup)
        [ -n "${SM_OIDC_ID:-}" ] && [ -n "${SM_OIDC_CLIENT:-}" ] && [ -n "${SM_OIDC_SECRET:-}" ] || die "OIDC-Daten fehlen"
        if ! occ app:list --output=json 2>/dev/null | grep -q '"user_oidc"'; then
            log "App user_oidc installieren"
            occ app:install user_oidc || die "user_oidc konnte nicht installiert werden (App-Store erreichbar?)"
        fi
        occ app:enable user_oidc >/dev/null 2>&1 || true
        log "OIDC-Anbieter $SM_OIDC_ID einrichten"
        occ user_oidc:provider "$SM_OIDC_ID" --clientid="$SM_OIDC_CLIENT" --clientsecret="$SM_OIDC_SECRET" \
            --discoveryuri="$SM_OIDC_DISCOVERY" --scope="openid email profile" --unique-uid=0 \
            --mapping-uid=preferred_username --mapping-display-name=name --mapping-email=email \
            >/dev/null || die "Anbieter konnte nicht eingerichtet werden"
        occ config:app:set user_oidc allow_multiple_user_backends --value=1 >/dev/null
        # existing accounts (same user ID as the authentik user name) are taken over instead of duplicated
        occ config:system:set user_oidc soft_auto_provision --type=boolean --value=true >/dev/null
        echo "SM_OK"
        ;;
    oidc_groups)
        # groups from authentik at every login: only the groups matching the whitelist are added and removed
        [ -n "${SM_OIDC_ID:-}" ] || die "OIDC-Anbieter fehlt"
        if [ "${SM_GROUP_PROVISIONING:-0}" = "1" ]; then
            [ -n "${SM_GROUP_REGEX:-}" ] || die "Keine Gruppen gewählt"
            log "Gruppen-Abgleich für Anbieter $SM_OIDC_ID einschalten"
            occ user_oidc:provider "$SM_OIDC_ID" --mapping-groups=groups --group-provisioning=1 \
                --group-whitelist-regex="$SM_GROUP_REGEX" >/dev/null || die "Gruppen-Abgleich nicht gesetzt (user_oidc zu alt?)"
        else
            log "Gruppen-Abgleich für Anbieter $SM_OIDC_ID ausschalten"
            occ user_oidc:provider "$SM_OIDC_ID" --group-provisioning=0 >/dev/null || die "Gruppen-Abgleich nicht geändert"
        fi
        echo "SM_OK"
        ;;
    oidc_remove)
        occ user_oidc:provider:delete "$SM_OIDC_ID" --force >/dev/null 2>&1 || \
            occ user_oidc:provider:delete "$SM_OIDC_ID" -f >/dev/null 2>&1 || true
        echo "SM_OK"
        ;;
    *) die "Unbekannte Aufgabe ${SM_TASK}" ;;
esac
