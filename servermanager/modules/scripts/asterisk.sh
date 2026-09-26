# shellcheck shell=bash
# Asterisk / FreePBX. Env: SM_TASK, extensions: SM_EXT, SM_NAME, SM_SECRET, SM_VM_EMAIL, SM_VM_PIN
have_fw() { command -v fwconsole >/dev/null 2>&1; }
ast() { asterisk -rx "$1" 2>/dev/null; }
ast_running() { ast "core show version" | grep -q '^Asterisk'; }
kv() { printf '%s=%s\n' "$1" "$2"; }

FPBX_CONF=/etc/freepbx.conf
conf_val() {  # value of $amp_conf['KEY'] in /etc/freepbx.conf
    [ -f "$FPBX_CONF" ] || return 0
    sed -n "s/.*\['$1'\][[:space:]]*=[[:space:]]*['\"]\([^'\"]*\)['\"].*/\1/p" "$FPBX_CONF" | head -n 1
}
db() {  # query the FreePBX database (tab separated, no header)
    local user pass name host
    user="$(conf_val AMPDBUSER)"; pass="$(conf_val AMPDBPASS)"
    name="$(conf_val AMPDBNAME)"; host="$(conf_val AMPDBHOST)"
    if [ -n "$user" ]; then
        MYSQL_PWD="$pass" mysql -h "${host:-localhost}" -u "$user" -B -N "${name:-asterisk}" -e "$1"
    else
        mysql -B -N asterisk -e "$1"
    fi
}
need_freepbx() { have_fw || die "Nur mit FreePBX möglich (fwconsole nicht gefunden)"; }
valid_ext() { [[ "${SM_EXT:-}" =~ ^[0-9]{2,8}$ ]] || die "Ungültige Nebenstelle (2-8 Ziffern)"; }
ext_exists() { [ -n "$(db "SELECT extension FROM users WHERE extension='$SM_EXT'")" ]; }
reload_pbx() {
    if have_fw; then
        fwconsole reload >/dev/null 2>&1 || fwconsole reload
    else
        ast "core reload" >/dev/null
    fi
}
csv() { local v="${1//\"/\"\"}"; printf '"%s"' "$v"; }

case "${SM_TASK:-status}" in
    status)
        kv version "$( (ast "core show version" || asterisk -V 2>/dev/null) | head -n 1)"
        if pgrep -x asterisk >/dev/null 2>&1 && ast_running; then kv active yes; else kv active no; fi
        if have_fw; then
            kv freepbx "$(db "SELECT version FROM modules WHERE modulename='framework'" 2>/dev/null | head -n 1)"
            kv freepbx_installed yes
        fi
        kv uptime "$(ast "core show uptime seconds" | sed -n 's/^System uptime: *\([0-9]*\).*/\1/p')"
        ast "core show channels count" | sed -n 's/^\([0-9]*\) active calls\{0,1\}\( .*\)\{0,1\}$/calls=\1/p; s/^\([0-9]*\) active channels\{0,1\}\( .*\)\{0,1\}$/channels=\1/p; s/^\([0-9]*\) calls\{0,1\} processed.*/processed=\1/p'
        grep -hE '^[[:space:]]*(external_media_address|external_signaling_address|local_net)[[:space:]]*=' \
            /etc/asterisk/pjsip*.conf 2>/dev/null | sed 's/[[:space:]]//g; s/^/nat_/' | sort -u
        grep -hE '^[[:space:]]*rtp(start|end)[[:space:]]*=' /etc/asterisk/rtp*.conf 2>/dev/null | sed 's/[[:space:]]//g' | sort -u
        echo "__TRANSPORTS__"; ast "pjsip show transports"
        echo "__REGS__"; ast "pjsip show registrations"
        echo "__SIPREG__"; ast "sip show registry" | grep -v "No such command"
        echo "__CONTACTS__"; ast "pjsip show contacts"
        echo "__ENDPOINTS__"; ast "pjsip list endpoints"
        echo "__EXT__"
        if have_fw; then
            db "SELECT u.extension, REPLACE(u.name, '\t', ' '), IFNULL(d.tech, ''), IFNULL(u.voicemail, '') FROM users u LEFT JOIN devices d ON d.id = u.extension ORDER BY LENGTH(u.extension), u.extension" 2>/dev/null
        fi
        echo "__END__"
        ;;
    check)
        if have_fw; then
            echo "__UPGRADES__"
            fwconsole ma showupgrades 2>/dev/null
            echo "__END__"
        fi
        ;;
    reload)
        log "Konfiguration neu laden"
        reload_pbx || die "Neu laden fehlgeschlagen"
        ;;
    restart)
        log "Asterisk neu starten (laufende Gespräche werden getrennt)"
        if have_fw; then
            fwconsole restart || die "fwconsole restart fehlgeschlagen"
        else
            systemctl restart asterisk || die "Neustart fehlgeschlagen"
        fi
        ;;
    module_upgrade)
        need_freepbx
        log "FreePBX-Module aktualisieren (fwconsole ma upgradeall)"
        fwconsole ma refreshsignatures >/dev/null 2>&1 || true
        fwconsole ma upgradeall || die "Aktualisierung der Module fehlgeschlagen"
        fwconsole chown >/dev/null 2>&1 || true
        reload_pbx || die "Neu laden nach dem Update fehlgeschlagen"
        ;;
    ext_add)
        need_freepbx; valid_ext
        [[ "${SM_SECRET:-}" =~ ^[A-Za-z0-9._-]{8,64}$ ]] || die "Ungültiges SIP-Passwort"
        [[ "${SM_VM_PIN:-}" =~ ^[0-9]{0,10}$ ]] || die "Ungültige Voicemail-PIN"
        ext_exists && die "Nebenstelle $SM_EXT existiert bereits"
        fwconsole ma list 2>/dev/null | grep -q bulkhandler \
            || die "Das FreePBX-Modul "Bulk Handler" fehlt (fwconsole ma downloadinstall bulkhandler)"
        f="$(mktemp --suffix=.csv)"; chmod 600 "$f"
        vm=novm; vme=no
        if [ -n "${SM_VM_PIN:-}" ] || [ -n "${SM_VM_EMAIL:-}" ]; then vm=default; vme=yes; fi
        {
            echo "extension,name,tech,secret,voicemail,voicemail_enable,voicemail_vmpwd,voicemail_email"
            printf '%s,%s,pjsip,%s,%s,%s,%s,%s\n' "$SM_EXT" "$(csv "${SM_NAME:-$SM_EXT}")" "$SM_SECRET" "$vm" "$vme" \
                "${SM_VM_PIN:-}" "$(csv "${SM_VM_EMAIL:-}")"
        } > "$f"
        log "Nebenstelle $SM_EXT anlegen"
        fwconsole bulkimport --type=extensions "$f"; rc=$?
        rm -f "$f"
        [ "$rc" -eq 0 ] || die "Import fehlgeschlagen"
        reload_pbx
        ext_exists || die "Nebenstelle $SM_EXT wurde nicht angelegt"
        echo "SM_OK"
        ;;
    ext_delete)
        need_freepbx; valid_ext
        ext_exists || die "Nebenstelle $SM_EXT existiert nicht"
        log "Nebenstelle $SM_EXT löschen"
        # shellcheck disable=SC2016 # PHP code
        SM_EXT="$SM_EXT" php -r '
            $bootstrap_settings["freepbx_auth"] = false;
            include "/etc/freepbx.conf";
            $ext = getenv("SM_EXT");
            $core = \FreePBX::Core();
            $core->delUser($ext);
            $core->delDevice($ext);
            try { $vm = \FreePBX::Voicemail(); if (method_exists($vm, "delMailbox")) { $vm->delMailbox($ext); } }
            catch (\Throwable $e) {}
        ' || die "Löschen fehlgeschlagen"
        reload_pbx
        ext_exists && die "Nebenstelle $SM_EXT ist noch vorhanden"
        echo "SM_OK"
        ;;
    ext_secret)
        need_freepbx; valid_ext
        [[ "${SM_SECRET:-}" =~ ^[A-Za-z0-9._-]{8,64}$ ]] || die "Ungültiges SIP-Passwort"
        ext_exists || die "Nebenstelle $SM_EXT existiert nicht"
        log "SIP-Passwort von $SM_EXT setzen"
        db "UPDATE sip SET data='$SM_SECRET' WHERE id='$SM_EXT' AND keyword='secret'" || die "Speichern fehlgeschlagen"
        [ "$(db "SELECT data FROM sip WHERE id='$SM_EXT' AND keyword='secret'")" = "$SM_SECRET" ] \
            || die "Kein SIP-Passwort für $SM_EXT gefunden"
        reload_pbx
        echo "SM_OK"
        ;;
    *) die "Unbekannte Aufgabe" ;;
esac
