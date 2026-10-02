# shellcheck shell=bash
# Env: SM_TASK
ISPC="${SM_ISPC_DIR:-/usr/local/ispconfig}"
CFG=$ISPC/server/lib/config.inc.php
[ -f "$CFG" ] || die "ISPConfig ist nicht installiert ($CFG fehlt)"

ispc_version() { grep -oE "ISPC_APP_VERSION', *'[^']+" "$CFG" | sed "s/.*'//"; }

ispc_port() {
    local p=""
    if [ -f /etc/apache2/sites-available/ispconfig.vhost ]; then
        p="$(grep -oE 'VirtualHost[^:]*:[0-9]+' /etc/apache2/sites-available/ispconfig.vhost | head -n 1 | grep -oE '[0-9]+$')"
    fi
    if [ -z "$p" ] && [ -f /etc/nginx/sites-available/ispconfig.vhost ]; then
        p="$(grep -oE 'listen[^0-9]*[0-9]+' /etc/nginx/sites-available/ispconfig.vhost | head -n 1 | grep -oE '[0-9]+$')"
    fi
    echo "${p:-8080}"
}

fetch() {
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        curl -fsSL -o "$2" "$1"
    fi
}

ispc_db() {  # query the ISPConfig database with the credentials of the ISPConfig server part
    local user pass name host
    user="$(sed -n "s/^\$conf\['db_user'\][[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" "$CFG" | head -n 1)"
    pass="$(sed -n "s/^\$conf\['db_password'\][[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" "$CFG" | head -n 1)"
    name="$(sed -n "s/^\$conf\['db_database'\][[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" "$CFG" | head -n 1)"
    host="$(sed -n "s/^\$conf\['db_host'\][[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" "$CFG" | head -n 1)"
    # query on stdin: values (e.g. secrets) never appear in the process list
    printf '%s\n' "$1" | MYSQL_PWD="$pass" mysql -h "${host:-localhost}" -u "${user:-ispconfig}" -B -N "${name:-dbispconfig}"
}

case "${SM_TASK}" in
    remote_user)
        # dedicated remote API user for the servermanager (only the needed function groups)
        [[ "${SM_ISPC_USER:-}" =~ ^[a-z][a-z0-9_-]{2,31}$ ]] || die "Ungültiger Benutzername"
        [[ "${SM_ISPC_PASS:-}" =~ ^[A-Za-z0-9]{20,64}$ ]] || die "Ungültiges Passwort"
        [[ "${SM_ISPC_FUNCS:-}" =~ ^[a-z_,]+$ ]] || die "Ungültige Funktionsliste"
        [[ "${SM_ISPC_IPS:-}" =~ ^[0-9a-fA-F.:/,]*$ ]] || die "Ungültige Adressliste"
        [ -d "$ISPC/interface/web" ] || die "Auf diesem Server ist keine ISPConfig-Oberfläche installiert (nur Server-Teil einer Multiserver-Installation?) - die Schnittstelle am Master einrichten"
        command -v php >/dev/null 2>&1 || die "php nicht gefunden"
        # shellcheck disable=SC2016 # PHP code
        # warnings/notices go to stderr, the result is marked: stdout noise of the PHP setup cannot spoil it
        out="$(SM_ISPC_FUNCS="$SM_ISPC_FUNCS" SM_ISPC_DIR="$ISPC" php -d display_errors=stderr -d log_errors=0 -r '
            $function_list = array();
            $files = glob(getenv("SM_ISPC_DIR") . "/interface/web/*/lib/remote.conf.php");
            foreach ($files ? $files : array() as $f) { include $f; }
            $need = explode(",", getenv("SM_ISPC_FUNCS"));
            $out = array();
            foreach (array_keys($function_list) as $k) {
                /* ISPConfig writes some groups with blanks after the commas; the key is stored verbatim */
                if (array_intersect(array_map("trim", explode(",", $k)), $need)) { $out[] = $k; }
            }
            echo "\nSM_FILES=" . count($files ? $files : array()) . "\nSM_GROUPS=" . implode(";", $out) . "\n";')"
        groups="$(printf '%s\n' "$out" | sed -n 's/^SM_GROUPS=//p' | tail -n 1)"
        files="$(printf '%s\n' "$out" | sed -n 's/^SM_FILES=//p' | tail -n 1)"
        [ "${files:-0}" -gt 0 ] || die "Keine Funktionslisten der Remote-API gefunden ($ISPC/interface/web/*/lib/remote.conf.php) - ISPConfig-Oberfläche vollständig installiert?"
        [ -n "$groups" ] || die "Funktionsgruppen der Remote-API nicht gefunden (${files} Funktionslisten gelesen, keine passende Gruppe)"
        [[ "$groups" =~ ^[A-Za-z0-9_,\;\ -]+$ ]] || die "Unerwartete Zeichen in den Funktionsgruppen der Remote-API"
        hash="$(printf '%s' "$SM_ISPC_PASS" | openssl passwd -6 -stdin)"
        [[ "$hash" =~ ^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$ ]] || die "Passwort-Hash fehlgeschlagen"
        has_ips="$(ispc_db "SHOW COLUMNS FROM remote_user LIKE 'remote_ips'" | head -n 1)"
        id="$(ispc_db "SELECT remote_userid FROM remote_user WHERE remote_username='$SM_ISPC_USER'" | head -n 1)"
        if [ -n "$id" ]; then
            ispc_db "UPDATE remote_user SET remote_password='$hash', remote_functions='$groups', remote_access='y' WHERE remote_userid=$id" \
                || die "Remote-Benutzer konnte nicht aktualisiert werden"
            log "Remote-Benutzer $SM_ISPC_USER aktualisiert"
        else
            ispc_db "INSERT INTO remote_user (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, remote_username, remote_password, remote_functions, remote_access) VALUES (1, 1, 'riud', 'riud', '', '$SM_ISPC_USER', '$hash', '$groups', 'y')" \
                || die "Remote-Benutzer konnte nicht angelegt werden"
            log "Remote-Benutzer $SM_ISPC_USER angelegt"
        fi
        if [ -n "$has_ips" ]; then
            ispc_db "UPDATE remote_user SET remote_ips='${SM_ISPC_IPS:-}' WHERE remote_username='$SM_ISPC_USER'"
        fi
        echo "version=$(ispc_version)"
        echo "port=$(ispc_port)"
        echo "groups=$(printf '%s\n' "$groups" | tr ';' '\n' | wc -l | tr -d ' ')"
        echo "SM_OK"
        ;;
    check)
        echo "installed=$(ispc_version)"
        tmp="$(mktemp)"
        if fetch https://www.ispconfig.org/downloads/ispconfig3_version.txt "$tmp"; then
            echo "latest=$(tr -d '[:space:]' < "$tmp")"
        fi
        rm -f "$tmp"
        ;;
    status)
        echo "version=$(ispc_version)"
        echo "port=$(ispc_port)"
        for s in apache2 nginx postfix dovecot mariadb mysql pure-ftpd-mysql bind9 rspamd redis-server \
                 clamav-daemon amavis fail2ban php8.4-fpm php8.3-fpm php8.2-fpm php8.1-fpm php7.4-fpm; do
            if systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q "^$s.service"; then
                echo "service=$s|$(systemctl is-active "$s" 2>/dev/null)"
            fi
        done
        if command -v postqueue >/dev/null 2>&1; then
            echo "mailqueue=$(postqueue -j 2>/dev/null | wc -l)"
        fi
        echo "cronlog_errors=$(tail -n 200 /var/log/ispconfig/cron.log 2>/dev/null | grep -ci 'error')"
        ;;
    mailqueue_flush)
        log "Mail-Warteschlange abarbeiten (postqueue -f)"
        postqueue -f
        sleep 3
        echo "Mails in der Warteschlange: $(postqueue -j 2>/dev/null | wc -l)"
        ;;
    update)
        command -v php >/dev/null 2>&1 || die "php-cli nicht gefunden"
        cur="$(ispc_version)"
        log "Installierte ISPConfig-Version: $cur"
        # Multi-server setups need the master DB root credentials which are not available locally.
        dbmaster="$(php -r "include '$CFG'; echo \$conf['dbmaster_host'] ?? '';" 2>/dev/null)"
        dbhost="$(php -r "include '$CFG'; echo \$conf['db_host'] ?? '';" 2>/dev/null)"
        if [ -n "$dbmaster" ] && [ "$dbmaster" != "$dbhost" ]; then
            die "Multiserver-Setup (Slave) erkannt - das Update muss hier manuell mit den Zugangsdaten des Masters erfolgen (ispconfig_update.sh)."
        fi
        rootpw="$(php -r "include '$ISPC/server/lib/mysql_clientdb.conf'; echo \$clientdb_password;" 2>/dev/null)"
        [ -n "$rootpw" ] || die "MySQL-Root-Passwort konnte nicht aus mysql_clientdb.conf gelesen werden"
        work="$(mktemp -d /tmp/sm-ispconfig.XXXXXX)"
        cd "$work" || die "tmp"
        log "Lade ISPConfig (stable) herunter"
        fetch https://www.ispconfig.org/downloads/ISPConfig-3-stable.tar.gz ISPConfig-3-stable.tar.gz || die "Download fehlgeschlagen"
        tar xzf ISPConfig-3-stable.tar.gz || die "Entpacken fehlgeschlagen"
        cd ispconfig3_install/install || die "Installationsverzeichnis fehlt"
        port="$(ispc_port)"
        log "Führe Update aus (Port $port, Dienste neu konfigurieren, Backup durch ISPConfig)"
        umask 077
        cat > autoupdate.ini <<INI
[update]
do_backup=yes
mysql_root_password=${rootpw}
mysql_master_hostname=
mysql_master_root_user=
mysql_master_root_password=
mysql_master_database=
reconfigure_permissions_in_master_database=no
reconfigure_services=yes
ispconfig_port=${port}
create_new_ispconfig_ssl_cert=no
reconfigure_crontab=yes
create_ssl_server_certs=no
ignore_hostname_dns=no
ispconfig_postfix_ssl_symlink=yes
ispconfig_pureftpd_ssl_symlink=yes
INI
        timeout 3600 php -q update.php --autoinstall=autoupdate.ini < /dev/null
        rc=$?
        rm -f autoupdate.ini
        cd / && rm -rf "$work"
        [ "$rc" -eq 0 ] || die "ISPConfig-Update fehlgeschlagen (Exit-Code $rc)"
        log "ISPConfig-Version jetzt: $(ispc_version)"
        ;;
    *) die "Unbekannte Aufgabe ${SM_TASK}" ;;
esac
