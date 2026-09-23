# shellcheck shell=bash
# Env: SM_TASK
ISPC=/usr/local/ispconfig
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

case "${SM_TASK}" in
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
