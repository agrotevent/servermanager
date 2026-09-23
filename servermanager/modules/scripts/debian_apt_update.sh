# shellcheck shell=bash
apt_update || die "apt-get update fehlgeschlagen"
log "Ausstehende Updates:"
apt-get -s dist-upgrade 2>/dev/null | awk '/^Inst / {print "  " $2 " " $3 " " $4}'
exit 0
