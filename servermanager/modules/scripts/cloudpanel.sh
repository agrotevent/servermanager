# shellcheck shell=bash
# CloudPanel (v2) via its command line clpctl. Env: SM_TASK and the values of the task (checked by the
# servermanager); passwords only come in through the environment and are never printed.
CLPCTL="${SM_CLPCTL:-clpctl}"
CLP_DB="${SM_CLP_DB:-/home/clp/htdocs/app/data/db.sq3}"
CLP_CERTS="${SM_CLP_CERTS:-/etc/nginx/ssl-certificates}"
command -v "$CLPCTL" >/dev/null 2>&1 || die "CloudPanel ist nicht installiert (clpctl fehlt)"

clp_version() {
    dpkg-query -W -f='${Version}' cloudpanel 2>/dev/null || "$CLPCTL" --version 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+)+' | head -n 1
}

# sites, users and databases from CloudPanel's own database (read only, without passwords and MFA secrets)
clp_dump() {
    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 fehlt – nur Sites aus der nginx-Konfiguration"
        return 1
    fi
    [ -r "$CLP_DB" ] || { warn "CloudPanel-Datenbank $CLP_DB nicht lesbar"; return 1; }
    python3 - "$CLP_DB" <<'PY'
import json, re, sqlite3, sys
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
db.row_factory = sqlite3.Row
secret = re.compile(r"pass|secret|mfa|token|hash|salt|key|otp|code", re.I)
def rows(table):
    try:
        cur = db.execute(f'SELECT * FROM "{table}"')
    except sqlite3.Error:
        return []
    return [{k: r[k] for k in r.keys() if not secret.search(k)} for r in cur]
out = {t: rows(t) for t in ("site", "user", "database", "database_user", "php_settings", "user_sites")}
print("__CLP__" + json.dumps(out, default=str))
PY
}

clp_certs() {
    local f d end issuer
    for f in "$CLP_CERTS"/*.crt; do
        [ -f "$f" ] || continue
        d="$(basename "$f" .crt)"
        end="$(openssl x509 -enddate -noout -in "$f" 2>/dev/null | sed 's/^notAfter=//')"
        issuer="$(openssl x509 -issuer -noout -in "$f" 2>/dev/null | sed -n 's/.*O *= *\([^,\/]*\).*/\1/p')"
        echo "cert=$d|$end|$issuer"
    done
}

ok_or_die() {   # run clpctl, show its output, SM_OK on success
    local out rc
    out="$("$CLPCTL" "$@" 2>&1)"
    rc=$?
    printf '%s\n' "$out" | grep -v -i 'password' || true
    [ "$rc" -eq 0 ] || die "clpctl $1 fehlgeschlagen: $(printf '%s' "$out" | grep -v -i 'password' | tail -n 2 | tr '\n' ' ')"
    echo "SM_OK"
}

case "${SM_TASK:-}" in
    status)
        echo "version=$(clp_version)"
        clp_dump || for f in /etc/nginx/sites-enabled/*.conf; do [ -f "$f" ] && echo "site=$(basename "$f" .conf)"; done
        clp_certs
        ;;
    site_add)
        case "${SM_TYPE:-}" in
            php) ok_or_die site:add:php --domainName="$SM_DOMAIN" --phpVersion="$SM_PHP" --vhostTemplate="${SM_VHOST:-Generic}" \
                     --siteUser="$SM_SITE_USER" --siteUserPassword="$SM_SITE_PASSWORD" ;;
            static) ok_or_die site:add:static --domainName="$SM_DOMAIN" --siteUser="$SM_SITE_USER" \
                        --siteUserPassword="$SM_SITE_PASSWORD" ;;
            nodejs) ok_or_die site:add:nodejs --domainName="$SM_DOMAIN" --nodejsVersion="$SM_NODE" --appPort="$SM_APP_PORT" \
                        --siteUser="$SM_SITE_USER" --siteUserPassword="$SM_SITE_PASSWORD" ;;
            python) ok_or_die site:add:python --domainName="$SM_DOMAIN" --pythonVersion="$SM_PYTHON" --appPort="$SM_APP_PORT" \
                        --siteUser="$SM_SITE_USER" --siteUserPassword="$SM_SITE_PASSWORD" ;;
            reverse-proxy) ok_or_die site:add:reverse-proxy --domainName="$SM_DOMAIN" --reverseProxyUrl="$SM_PROXY_URL" \
                               --siteUser="$SM_SITE_USER" --siteUserPassword="$SM_SITE_PASSWORD" ;;
            *) die "Unbekannter Site-Typ ${SM_TYPE:-}" ;;
        esac
        ;;
    site_delete) ok_or_die site:delete --domainName="$SM_DOMAIN" --force ;;
    cert)
        if [ -n "${SM_SAN:-}" ]; then
            ok_or_die lets-encrypt:install:certificate --domainName="$SM_DOMAIN" --subjectAlternativeName="$SM_SAN"
        else
            ok_or_die lets-encrypt:install:certificate --domainName="$SM_DOMAIN"
        fi
        ;;
    db_add) ok_or_die db:add --domainName="$SM_DOMAIN" --databaseName="$SM_DB" --databaseUserName="$SM_DB_USER" \
                --databaseUserPassword="$SM_DB_PASSWORD" ;;
    user_add)
        args=(user:add --userName="$SM_USER" --email="$SM_EMAIL" --firstName="${SM_FIRST:-$SM_USER}"
              --lastName="${SM_LAST:--}" --password="$SM_PASSWORD" --role="$SM_ROLE" --timezone="${SM_TZ:-UTC}" --status=1)
        [ "$SM_ROLE" = "user" ] && args+=(--sites="$SM_SITES")
        ok_or_die "${args[@]}"
        ;;
    user_delete) ok_or_die user:delete --userName="$SM_USER" ;;
    user_password) ok_or_die user:reset:password --userName="$SM_USER" --password="$SM_PASSWORD" ;;
    user_mfa_off) ok_or_die user:disable:mfa --userName="$SM_USER" ;;
    cloudflare_ips) ok_or_die cloudflare:update:ips ;;
    update)
        command -v clp-update >/dev/null 2>&1 || die "clp-update fehlt"
        log "CloudPanel aktualisieren (clp-update)"
        clp-update || die "clp-update fehlgeschlagen"
        echo "version=$(clp_version)"
        ;;
    *) die "Unbekannte Aufgabe ${SM_TASK:-}" ;;
esac
