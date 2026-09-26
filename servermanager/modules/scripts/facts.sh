# shellcheck shell=bash
# Collects inventory information. Output: key=value lines (multi value keys repeat).
# Env: SM_NC_PATH (optional configured nextcloud path)

kv() { printf '%s=%s\n' "$1" "$2"; }

if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
fi
kv os_id "${ID:-}"
kv os_version "${VERSION_ID:-}"
kv os_name "${PRETTY_NAME:-}"
kv os_codename "${VERSION_CODENAME:-}"
kv debian_version "$(cat /etc/debian_version 2>/dev/null)"
kv hostname "$(hostname -f 2>/dev/null || hostname)"
kv kernel "$(uname -r)"
kv arch "$(uname -m)"
kv virt "$(systemd-detect-virt 2>/dev/null || echo none)"
kv uptime "$(cut -d. -f1 /proc/uptime)"
kv load "$(cut -d' ' -f1-3 /proc/loadavg)"
kv cpus "$(nproc 2>/dev/null || echo 1)"
awk '/^MemTotal:/{print "mem_total="$2} /^MemAvailable:/{print "mem_avail="$2}
     /^SwapTotal:/{print "swap_total="$2} /^SwapFree:/{print "swap_free="$2}' /proc/meminfo
df -P -k -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null \
    | awk 'NR>1 && $1 !~ /^(udev|none)$/ {print "disk="$6"|"$2"|"$3"|"$4}' | head -n 20
kv ip "$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' | head -n 5 | tr '\n' ' ')"

# ---- reboot required --------------------------------------------------
reboot=0
reason=""
if [ -f /var/run/reboot-required ]; then
    reboot=1
    reason="$(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null)"
fi
running="$(uname -r)"
newest="$(find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null | sed 's/^vmlinuz-//' | sort -V | tail -n 1)"
if [ -n "$newest" ] && [ "$newest" != "$running" ]; then
    reboot=1
    reason="$reason kernel:$newest"
fi
# Debian: same ABI but updated kernel package
if command -v dpkg-query >/dev/null 2>&1; then
    built="$(uname -v | grep -oE 'Debian [^ ]+' | awk '{print $2}')"
    pkgver="$(dpkg-query -W -f='${Version}' "linux-image-$running" 2>/dev/null)"
    if [ -n "$built" ] && [ -n "$pkgver" ] && [ "$built" != "$pkgver" ]; then
        reboot=1
        reason="$reason kernel-package:$pkgver"
    fi
fi
kv reboot_required "$reboot"
kv reboot_reason "$(echo "$reason" | xargs 2>/dev/null)"

kv failed_units "$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
if command -v needrestart >/dev/null 2>&1; then
    kv needrestart_services "$(needrestart -b -r l 2>/dev/null | grep -c '^NEEDRESTART-SVC')"
fi

# ---- apt ---------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    kv apt 1
    stamp=/var/lib/apt/periodic/update-success-stamp
    if [ -f "$stamp" ]; then
        kv apt_updated "$(stat -c %Y "$stamp")"
    else
        kv apt_updated "$(find /var/lib/apt/lists -maxdepth 1 -type f -printf '%T@\n' 2>/dev/null | sort -n | tail -n 1 | cut -d. -f1)"
    fi
    kv apt_held "$(apt-mark showhold 2>/dev/null | tr '\n' ' ')"
    kv dpkg_audit "$(dpkg --audit 2>/dev/null | head -c 300 | tr '\n' ' ')"
    # Simulated dist-upgrade -> list of pending package updates
    apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | awk '
        /^Inst / {
            name=$2; cur=""; i=3
            if ($3 ~ /^\[/) { cur=$3; gsub(/[\[\]]/, "", cur); i=4 }
            new=$i; gsub(/\(/, "", new)
            origin=$(i+1)
            sec = ($0 ~ /[Ss]ecurity/) ? 1 : 0
            print "pkg=" name "|" cur "|" new "|" origin "|" sec
        }' | head -n 2000
fi

# ---- detected software -------------------------------------------------
if command -v docker >/dev/null 2>&1; then
    kv docker_version "$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
    kv docker_running "$(docker ps -q 2>/dev/null | wc -l)"
    kv docker_total "$(docker ps -aq 2>/dev/null | wc -l)"
fi
if command -v pveversion >/dev/null 2>&1; then
    kv pve_version "$(pveversion 2>/dev/null | cut -d/ -f2)"
    kv pve_guests "$( (qm list 2>/dev/null | tail -n +2; pct list 2>/dev/null | tail -n +2) | wc -l)"
fi
if [ -x /usr/local/bin/newt ] || command -v newt >/dev/null 2>&1; then
    kv newt_version "$( (newt --version 2>/dev/null || /usr/local/bin/newt --version 2>/dev/null) | head -n 1 | tr -d '\r')"
    kv newt_active "$(systemctl is-active newt 2>/dev/null)"
elif command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Image}}' 2>/dev/null | grep -q 'fosrl/newt'; then
    kv newt_version "docker"
    kv newt_active "$(docker ps --format '{{.Image}}' 2>/dev/null | grep -q 'fosrl/newt' && echo active || echo inactive)"
fi
ispc=/usr/local/ispconfig/server/lib/config.inc.php
if [ -f "$ispc" ]; then
    kv ispconfig_version "$(grep -oE "ISPC_APP_VERSION', *'[^']+" "$ispc" | sed "s/.*'//")"
fi

# Nextcloud installations (path|version)
nc_seen=""
for occ in "${SM_NC_PATH:+$SM_NC_PATH/occ}" /var/www/nextcloud/occ /var/www/html/occ /var/www/*/occ \
           /var/www/*/web/occ /var/www/*/*/occ /var/www/clients/*/*/web/occ /srv/www/*/occ /srv/nextcloud/occ; do
    [ -n "$occ" ] && [ -f "$occ" ] || continue
    dir="$(dirname "$(readlink -f "$occ")")"
    [ -f "$dir/version.php" ] || continue
    case " $nc_seen " in *" $dir "*) continue ;; esac
    nc_seen="$nc_seen $dir"
    ver="$(grep -oE "OC_VersionString *= *'[^']+" "$dir/version.php" | sed "s/.*'//")"
    kv nextcloud "$dir|$ver"
done
if command -v nextcloud.occ >/dev/null 2>&1; then
    kv nextcloud "snap|$(snap list nextcloud 2>/dev/null | awk 'NR==2{print $2}')"
fi
exit 0
