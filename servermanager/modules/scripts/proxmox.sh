# shellcheck shell=bash
# Env: SM_TASK, SM_NODE, SM_TYPE, SM_VMID, SM_OP, SM_STORAGE, SM_MODE
command -v pveversion >/dev/null 2>&1 || die "Proxmox VE ist nicht installiert"

check_guest() {
    [[ "${SM_NODE}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || die "Ungültiger Node-Name"
    [[ "${SM_VMID}" =~ ^[0-9]+$ ]] || die "Ungültige VMID"
    case "${SM_TYPE}" in qemu|lxc) ;; *) die "Ungültiger Gast-Typ" ;; esac
}

on_node() {
    # run a command on the node that hosts the guest (cluster nodes trust each other via SSH)
    if [ "${SM_NODE}" = "$(hostname)" ] || [ "${SM_NODE}" = "$(hostname -s)" ]; then
        "$@"
    else
        ssh -o BatchMode=yes -o ConnectTimeout=10 "root@${SM_NODE}" -- "$(printf '%q ' "$@")"
    fi
}

case "${SM_TASK}" in
    guest_action)
        check_guest
        case "${SM_OP}" in start|stop|shutdown|reboot|suspend|resume) ;; *) die "Ungültige Aktion" ;; esac
        log "${SM_TYPE}/${SM_VMID} auf ${SM_NODE}: ${SM_OP}"
        pvesh create "/nodes/${SM_NODE}/${SM_TYPE}/${SM_VMID}/status/${SM_OP}" || die "Aktion fehlgeschlagen"
        sleep 2
        pvesh get "/nodes/${SM_NODE}/${SM_TYPE}/${SM_VMID}/status/current" --output-format yaml 2>/dev/null \
            | grep -E '^(status|name|uptime):'
        ;;
    vzdump)
        check_guest
        mode="${SM_MODE:-snapshot}"
        case "$mode" in snapshot|suspend|stop) ;; *) die "Ungültiger Modus" ;; esac
        args=(vzdump "${SM_VMID}" --mode "$mode" --compress zstd)
        if [ -n "${SM_STORAGE:-}" ]; then
            [[ "${SM_STORAGE}" =~ ^[A-Za-z0-9._-]+$ ]] || die "Ungültiger Storage-Name"
            args+=(--storage "${SM_STORAGE}")
        fi
        log "Sicherung von ${SM_VMID} auf ${SM_NODE} (${args[*]})"
        on_node "${args[@]}" || die "vzdump fehlgeschlagen"
        ;;
    upgrade_check)
        major="$(pveversion | grep -oE 'pve-manager/[0-9]+' | cut -d/ -f2)"
        if [ "$major" = "8" ] && command -v pve8to9 >/dev/null 2>&1; then
            log "pve8to9 --full"
            pve8to9 --full
        elif [ "$major" = "7" ] && command -v pve7to8 >/dev/null 2>&1; then
            log "pve7to8 --full"
            pve7to8 --full
        else
            log "Kein Upgrade-Checker für Proxmox VE $major verfügbar."
            pveversion -v
        fi
        ;;
    *) die "Unbekannte Aufgabe ${SM_TASK}" ;;
esac
