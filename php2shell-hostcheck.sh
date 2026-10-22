#!/usr/bin/env bash
#
# php2shell-hostcheck — read-only host check for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619)
#
# Checks the PHP that actually runs on this server: CLI, PHP-FPM, CGI,
# Apache mod_php, LiteSpeed lsphp, and cPanel / Plesk / Remi / CloudLinux
# builds. It looks at:
#   - the real runtime version vs. the fixed upstream releases
#   - distro backports (Debian/Ubuntu changelogs, RPM changelogs)
#   - running workers still using an old, replaced binary (restart needed)
#   - temporary mitigation settings
#   - optional basic compromise indicators (--ioc)
#
# READ-ONLY: it never changes files, settings or services, and it sends
# no network traffic. It is an indicator check, not proof of safety.
#
# MIT License — https://github.com/Charlie-Netdevops/php2shell-hostcheck

TOOL_VERSION="0.1.0"
DATA_DATE="2026-10-22"

# Fixed upstream releases (PHP security release, 21 Oct 2026).
# Edit here if PHP publishes a follow-up release.
declare -A FIXED=( [8.2]=35 [8.3]=36 [8.4]=27 [8.5]=12 )
CVES="CVE-2026-109618|CVE-2026-109619"
DEFAULT_SINCE="2026-10-17"   # earliest publicly reported exploitation attempt

# ---------------------------------------------------------------- options ---

OUT_JSON=0
DO_IOC=0
DEEP=0
SINCE="$DEFAULT_SINCE"
WEBROOTS=()
USE_COLOR=auto

usage() {
  cat <<EOF
php2shell-hostcheck $TOOL_VERSION — read-only check for PHP2Shell
(CVE-2026-109618 / CVE-2026-109619) on this host.

Usage: sudo ./php2shell-hostcheck.sh [options]

Options:
  --json            Machine-readable JSON output (for n8n, cron, SIEM)
  --ioc             Also look for basic compromise indicators
  --webroot DIR     Web root to scan with --ioc (repeatable; implies --ioc).
                    Default: /var/www, /srv/www, /home/*/public_html, ...
  --since DATE      Look for changes since DATE (default $DEFAULT_SINCE)
  --deep            With --ioc, scan ALL PHP files for webshell patterns,
                    not just recently changed ones (slower)
  --no-color        Disable colours
  -V, --version     Show version
  -h, --help        Show this help

Exit codes:
  0  all PHP runtimes found are patched, nothing else flagged
  1  vulnerable: unpatched or end-of-life PHP, or workers need a restart
  2  needs attention: unknown version, EOL with backport, or indicators found
  3  no PHP runtime found
 64  bad arguments

Run as root for full results (other users' processes, crontabs, configs).
Only run it on systems you own or are authorised to check.
EOF
}

die() { echo "error: $*" >&2; exit 64; }

while [ $# -gt 0 ]; do
  case "$1" in
    --json) OUT_JSON=1 ;;
    --ioc) DO_IOC=1 ;;
    --deep) DEEP=1 ;;
    --webroot)
      [ -n "${2:-}" ] || die "--webroot needs a directory"
      [ -d "$2" ] || die "--webroot: '$2' is not a directory"
      WEBROOTS+=("$2"); DO_IOC=1; shift ;;
    --since)
      [ -n "${2:-}" ] || die "--since needs a date (YYYY-MM-DD)"
      date -d "$2" +%F >/dev/null 2>&1 || die "--since: '$2' is not a valid date"
      SINCE=$(date -d "$2" +%F); shift ;;
    --no-color) USE_COLOR=0 ;;
    -V|--version) echo "php2shell-hostcheck $TOOL_VERSION (data $DATA_DATE)"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; echo >&2; usage >&2; exit 64 ;;
  esac
  shift
done

# ---------------------------------------------------------------- helpers ---

have() { command -v "$1" >/dev/null 2>&1; }
if have timeout; then T() { timeout 10 "$@"; }; else T() { "$@"; }; fi

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

if [ "$USE_COLOR" = auto ]; then
  if [ -t 1 ] && [ "$OUT_JSON" -eq 0 ]; then USE_COLOR=1; else USE_COLOR=0; fi
fi
if [ "$USE_COLOR" -eq 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; BLD=""; DIM=""; RST=""
fi

json_esc() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}; s=${s//$'\r'/}
  printf '%s' "$s"
}

NOTES=()
note() { NOTES+=("$1"); }

# Findings (restart + indicators): severity | title | detail
F_SEV=(); F_TITLE=(); F_DETAIL=()
finding() { F_SEV+=("$1"); F_TITLE+=("$2"); F_DETAIL+=("$3"); }

shopt -s nullglob

# -------------------------------------------------------------- discovery ---

declare -A SEEN
B_PATH=(); B_KIND=()

add_bin() { # path kind
  local p=$1 kind=$2 r
  [ -f "$p" ] || return
  [ "$kind" = mod_php ] || [ -x "$p" ] || return
  r=$(readlink -f "$p" 2>/dev/null || echo "$p")
  [ -n "${SEEN[$r]:-}" ] && return
  SEEN[$r]=1
  B_PATH+=("$r"); B_KIND+=("$kind")
}

kind_of() {
  case "$(basename "$1")" in
    *fpm*) echo fpm ;;
    *cgi*) echo cgi ;;
    lsphp*) echo litespeed ;;
    *) echo cli ;;
  esac
}

discover() {
  local p
  for p in $(type -ap php php-cgi php-fpm lsphp 2>/dev/null) \
      /usr/bin/php /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/sbin/php-fpm* \
      /usr/local/bin/php /usr/local/bin/php[0-9]* /usr/local/bin/php-cgi* /usr/local/sbin/php-fpm* \
      /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/bin/php-cgi /opt/remi/php*/root/usr/sbin/php-fpm \
      /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/php-cgi /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
      /opt/plesk/php/*/bin/php /opt/plesk/php/*/bin/php-cgi /opt/plesk/php/*/sbin/php-fpm \
      /opt/alt/php*/usr/bin/php /opt/alt/php*/usr/bin/php-cgi /opt/alt/php*/usr/sbin/php-fpm \
      /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php \
      /usr/local/php*/bin/php /usr/local/php*/sbin/php-fpm; do
    case "$(basename "$p")" in *config*|*phpize*|*dbg*) continue ;; esac
    add_bin "$p" "$(kind_of "$p")"
  done
  for p in /usr/lib/apache2/modules/libphp*.so /etc/httpd/modules/libphp*.so \
      /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so \
      /usr/local/apache2/modules/libphp*.so /usr/local/apache/modules/libphp*.so; do
    add_bin "$p" mod_php
  done
}

# -------------------------------------------------------- version + status ---

pkg_owner() {
  if have dpkg-query; then
    dpkg-query -S "$1" 2>/dev/null | head -n1 | cut -d: -f1
  elif have rpm; then
    rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | grep -v 'not owned' | head -n1
  fi
}

pkg_version() {
  if have dpkg-query; then
    dpkg-query -W -f='${Version}' "$1" 2>/dev/null
  elif have rpm; then
    rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null
  fi
}

get_version() { # path kind pkg
  local path=$1 kind=$2 pkg=$3 v=""
  if [ "$kind" = mod_php ]; then
    if [ -n "$pkg" ]; then
      v=$(pkg_version "$pkg" | sed 's/^[0-9]*://' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    fi
    [ -z "$v" ] && v=$(grep -aoE 'PHP/[0-9]+\.[0-9]+\.[0-9]+' "$path" 2>/dev/null | head -n1 | cut -d/ -f2)
  else
    v=$(T "$path" -n -v 2>/dev/null | head -n1 | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d' ' -f2)
  fi
  printf '%s' "$v"
}

CHANGELOG_FOUND=0
backported() { # pkg branch -> 0 if a distro changelog lists the CVEs
  local pkg=$1 br=$2 d f
  CHANGELOG_FOUND=0
  [ -z "$pkg" ] && return 1
  if ! have dpkg-query && have rpm; then
    local cl
    cl=$(rpm -q --changelog "$pkg" 2>/dev/null)
    [ -n "$cl" ] && CHANGELOG_FOUND=1
    printf '%s\n' "$cl" | grep -qE "$CVES" && return 0
    return 1
  fi
  for d in "/usr/share/doc/$pkg" "/usr/share/doc/php$br-common" "/usr/share/doc/php$br"; do
    for f in "$d/changelog.Debian.gz" "$d/changelog.gz" "$d/NEWS.Debian.gz"; do
      [ -f "$f" ] || continue
      CHANGELOG_FOUND=1
      zgrep -qE "$CVES" "$f" 2>/dev/null && return 0
    done
  done
  return 1
}

classify() { # version pkg -> C_STATUS C_NOTE
  local v=$1 pkg=$2 br patch major minor fixed
  C_STATUS=UNKNOWN; C_NOTE=""
  if [ -z "$v" ]; then
    C_NOTE="could not read the version — check it by hand (php -v / php-fpm -v / phpinfo)"
    return
  fi
  br=${v%.*}; patch=${v##*.}; major=${br%%.*}; minor=${br#*.}
  fixed=${FIXED[$br]:-}
  if [ -n "$fixed" ]; then
    if [ "$patch" -ge "$fixed" ]; then
      C_STATUS=PATCHED; C_NOTE="at or above the fixed release $br.$fixed"; return
    fi
    if backported "$pkg" "$br"; then
      C_STATUS=PATCHED_BACKPORT; C_NOTE="distro package $pkg lists the CVE fix (backport)"; return
    fi
    C_STATUS=VULNERABLE; C_NOTE="update to $br.$fixed or newer, then restart PHP-FPM / the web server"
    [ "$CHANGELOG_FOUND" -eq 0 ] && [ -n "$pkg" ] && C_NOTE="$C_NOTE (no distro changelog found to check for a backport)"
    return
  fi
  if [ "$major" -lt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -lt 2 ]; }; then
    if backported "$pkg" "$br"; then
      C_STATUS=EOL_BACKPORT
      C_NOTE="distro backport found, but $br is end-of-life — plan an upgrade to 8.3 or newer"
      return
    fi
    C_STATUS=EOL
    C_NOTE="end-of-life branch with no official fix — upgrade to 8.3+, or isolate/take offline"
    return
  fi
  C_NOTE="branch $br is not in this tool's data ($DATA_DATE) — check php.net"
}

ini_read() { # path kind -> I_UP I_POST I_MEM I_FEB
  local path=$1 kind=$2 out
  I_UP="?"; I_POST="?"; I_MEM="?"; I_FEB="n/a"
  [ "$kind" = mod_php ] && return
  out=$(T "$path" -i 2>/dev/null)
  [ -z "$out" ] && return
  I_UP=$(printf '%s\n' "$out" | awk -F' => ' '$1=="session.upload_progress.enabled"{print $2; exit}')
  I_POST=$(printf '%s\n' "$out" | awk -F' => ' '$1=="post_max_size"{print $2; exit}')
  I_MEM=$(printf '%s\n' "$out" | awk -F' => ' '$1=="memory_limit"{print $2; exit}')
  local feb
  feb=$(printf '%s\n' "$out" | awk -F' => ' '$1=="fatal_error_backtraces"{print $2; exit}')
  [ -n "$feb" ] && I_FEB=$feb
  [ -z "$I_UP" ] && I_UP="n/a"
  [ -z "$I_POST" ] && I_POST="?"
  [ -z "$I_MEM" ] && I_MEM="?"
}

R_PATH=(); R_KIND=(); R_VER=(); R_PKG=(); R_STATUS=(); R_NOTE=()
R_UP=(); R_POST=(); R_MEM=(); R_FEB=()

check_runtimes() {
  local i path kind pkg ver
  for i in "${!B_PATH[@]}"; do
    path=${B_PATH[$i]}; kind=${B_KIND[$i]}
    pkg=$(pkg_owner "$path")
    ver=$(get_version "$path" "$kind" "$pkg")
    classify "$ver" "$pkg"
    ini_read "$path" "$kind"
    R_PATH+=("$path"); R_KIND+=("$kind"); R_VER+=("$ver"); R_PKG+=("$pkg")
    R_STATUS+=("$C_STATUS"); R_NOTE+=("$C_NOTE")
    R_UP+=("$I_UP"); R_POST+=("$I_POST"); R_MEM+=("$I_MEM"); R_FEB+=("$I_FEB")
  done
}

# ---------------------------------------------------- mitigation overrides ---

OVERRIDES=()
check_overrides() {
  local dirs=() d line
  for d in /etc/php/*/fpm/pool.d /etc/php-fpm.d /etc/opt/remi/php*/php-fpm.d \
      /opt/cpanel/ea-php*/root/etc/php-fpm.d /opt/plesk/php/*/etc/php-fpm.d \
      /usr/local/etc/php-fpm.d /etc/php*/php-fpm.d /etc/apache2 /etc/httpd; do
    [ -d "$d" ] && dirs+=("$d")
  done
  [ ${#dirs[@]} -eq 0 ] && return
  while IFS= read -r line; do
    [ -n "$line" ] && OVERRIDES+=("$line")
  done < <(grep -rsHE '^[[:space:]]*(php_(admin_)?(value|flag)[[:space:][]+session\.upload_progress\.enabled|php_admin_(value|flag)\[(memory_limit|post_max_size)\])' "${dirs[@]}" 2>/dev/null | head -n 50)
}

# ------------------------------------------------- running process checks ---

check_restart() {
  local pid exe maps stale=() seen_key
  declare -A done_exe
  for pid in /proc/[0-9]*; do
    pid=${pid#/proc/}
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    case "$exe" in
      *php*" (deleted)")
        seen_key=$exe ;;
      *apache2*|*httpd*)
        maps=$(grep -m1 -oE '/[^ ]*libphp[^ ]*\.so \(deleted\)' "/proc/$pid/maps" 2>/dev/null)
        [ -z "$maps" ] && continue
        seen_key="$exe uses replaced $maps" ;;
      *) continue ;;
    esac
    [ -n "${done_exe[$seen_key]:-}" ] && continue
    done_exe[$seen_key]=1
    stale+=("PID $pid: $seen_key")
  done
  if [ ${#stale[@]} -gt 0 ]; then
    finding high "Running PHP still uses the old binary — restart needed" \
      "PHP was updated on disk, but these processes are still running the replaced (possibly vulnerable) code. Restart PHP-FPM / Apache / LiteSpeed:
$(printf '  %s\n' "${stale[@]}")"
  fi
  [ "$IS_ROOT" -eq 0 ] && note "Not running as root: processes owned by other users (php-fpm master, apache) could not be checked for stale binaries."
}

check_containers() {
  if have docker; then
    local n
    n=$(T docker ps -q 2>/dev/null | wc -l)
    if [ "${n:-0}" -gt 0 ]; then
      note "$n running Docker container(s) were NOT scanned. Copy this script into each PHP container and run it there (docker cp + docker exec)."
    fi
  fi
}

# ------------------------------------------------------------- indicators ---

SUSP_RE='(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|\$_(GET|POST|REQUEST|COOKIE|SERVER))|(system|shell_exec|passthru|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\('

list_some() { # print up to N lines, then "... and X more"
  local max=$1 total
  local -a lines=()
  mapfile -t lines
  total=${#lines[@]}
  [ "$total" -eq 0 ] && return
  printf '  %s\n' "${lines[@]:0:$max}"
  [ "$total" -gt "$max" ] && printf '  ... and %d more\n' "$((total - max))"
}

ioc_scan() {
  local roots=() r
  if [ ${#WEBROOTS[@]} -gt 0 ]; then
    roots=("${WEBROOTS[@]}")
  else
    for r in /var/www /srv/www /srv/http /usr/share/nginx/html /home/*/public_html /var/www/vhosts; do
      [ -d "$r" ] && roots+=("$r")
    done
  fi
  IOC_ROOTS=("${roots[@]}")

  local php_names=( \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.phar' -o -name '*.inc' \) )

  if [ ${#roots[@]} -eq 0 ]; then
    note "No web root found for --ioc. Pass one with --webroot DIR."
  else
    # 1. PHP files changed since the date
    local recent
    recent=$(find "${roots[@]}" -xdev -type f "${php_names[@]}" -newermt "$SINCE" 2>/dev/null | sort)
    if [ -n "$recent" ]; then
      finding medium "PHP files changed since $SINCE" \
        "$(printf '%s\n' "$recent" | wc -l) file(s). Plugin/theme/app updates also cause this — review anything you did not change:
$(printf '%s\n' "$recent" | list_some 25)"
    fi

    # 2. Webshell-like code
    local hits
    if [ "$DEEP" -eq 1 ]; then
      hits=$(find "${roots[@]}" -xdev -type f "${php_names[@]}" -print0 2>/dev/null | xargs -0 -r grep -lEi -- "$SUSP_RE" 2>/dev/null | sort)
    elif [ -n "$recent" ]; then
      hits=$(printf '%s\n' "$recent" | tr '\n' '\0' | xargs -0 -r grep -lEi -- "$SUSP_RE" 2>/dev/null | sort)
    fi
    if [ -n "$hits" ]; then
      finding high "Webshell-like code patterns" \
        "These files run code taken straight from a request or decode hidden code — common webshell signs (false positives happen):
$(printf '%s\n' "$hits" | list_some 25)"
    fi

    # 3. PHP inside upload folders
    local upl
    upl=$(find "${roots[@]}" -xdev -type f "${php_names[@]}" \( -path '*/uploads/*' -o -path '*/upload/*' -o -path '*/media/*' \) 2>/dev/null | grep -v '/index\.php$' | sort)
    if [ -n "$upl" ]; then
      finding medium "PHP files inside upload folders" \
        "Upload folders normally hold images and documents, not code:
$(printf '%s\n' "$upl" | list_some 25)"
    fi
  fi

  # 4. PHP in temp folders
  local tmpphp
  tmpphp=$(find /tmp /var/tmp /dev/shm -xdev -maxdepth 4 -type f "${php_names[@]}" 2>/dev/null | sort)
  if [ -n "$tmpphp" ]; then
    finding medium "PHP files in temp folders" "$(printf '%s\n' "$tmpphp" | list_some 25)"
  fi

  # 5. Web-user crontabs and recently changed system cron
  local u f crons=()
  for u in www-data apache nginx nobody http wwwrun lsadm; do
    for f in "/var/spool/cron/crontabs/$u" "/var/spool/cron/$u"; do
      [ -f "$f" ] && crons+=("$f ($(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null || echo '?') active line(s))")
    done
  done
  if [ ${#crons[@]} -gt 0 ]; then
    finding high "Crontab exists for a web-server user" \
      "Attackers often add persistence here. Review:
$(printf '  %s\n' "${crons[@]}")"
  fi
  [ "$IS_ROOT" -eq 0 ] && note "Not running as root: web-user crontabs could not be read."
  local syscron
  syscron=$(find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily -xdev -type f -newermt "$SINCE" 2>/dev/null | sort)
  if [ -n "$syscron" ]; then
    finding medium "System cron files changed since $SINCE" "$(printf '%s\n' "$syscron" | list_some 25)"
  fi

  # 6. Accounts
  local uid0
  uid0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null)
  if [ -n "$uid0" ]; then
    finding high "Extra accounts with UID 0 (root rights)" "$(printf '  %s\n' $uid0)"
  fi
  if [ -n "$(find /etc/passwd -newermt "$SINCE" 2>/dev/null)" ]; then
    finding medium "User list (/etc/passwd) changed since $SINCE" \
      "Check for accounts you did not create:  awk -F: '\$3>=1000' /etc/passwd"
  fi

  # 7. Out-of-memory errors in PHP / web logs (exploit attempts trigger these)
  local logs=() lf oom=() c
  for lf in /var/log/php*fpm*.log /var/log/php-fpm/*.log /var/log/apache2/error.log \
      /var/log/apache2/*error*.log /var/log/httpd/error_log /var/log/httpd/*error*log \
      /var/log/nginx/error.log /usr/local/lsws/logs/error.log; do
    [ -f "$lf" ] && logs+=("$lf")
  done
  for lf in "${logs[@]}"; do
    c=$(grep -c 'Allowed memory size of' "$lf" 2>/dev/null)
    [ "${c:-0}" -gt 0 ] && oom+=("$lf: $c")
  done
  if [ ${#oom[@]} -gt 0 ]; then
    finding info "PHP out-of-memory errors in current logs" \
      "PHP2Shell exploit attempts deliberately trigger these. They can also be normal app issues — look for bursts around POST requests:
$(printf '  %s\n' "${oom[@]}")"
  fi

  # 8. Established outbound connections from PHP workers
  if have ss; then
    local conns
    conns=$(ss -tnpH state established 2>/dev/null | grep -E '"(php[^"]*|lsphp)"' \
      | awk '{print $4, "->", $5, $6}' \
      | grep -vE -- '-> (127\.|\[::1\]|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | sort -u)
    if [ -n "$conns" ]; then
      finding info "PHP workers with outbound connections to public addresses" \
        "Often normal (APIs, payment gateways, update checks). Unknown destinations deserve a look:
$(printf '%s\n' "$conns" | list_some 20)"
    fi
  fi
}

# ---------------------------------------------------------------- run it ---

discover
check_runtimes
check_overrides
check_restart
check_containers
IOC_ROOTS=()
[ "$DO_IOC" -eq 1 ] && ioc_scan

# Overall result
N_VULN=0; N_ATTN=0
for s in "${R_STATUS[@]}"; do
  case "$s" in
    VULNERABLE|EOL) N_VULN=$((N_VULN+1)) ;;
    UNKNOWN|EOL_BACKPORT) N_ATTN=$((N_ATTN+1)) ;;
  esac
done
N_RESTART=0; N_IOC=0
for i in "${!F_SEV[@]}"; do
  case "${F_TITLE[$i]}" in
    *"restart needed"*) N_RESTART=$((N_RESTART+1)) ;;
    *) [ "${F_SEV[$i]}" != info ] && N_IOC=$((N_IOC+1)) ;;
  esac
done

if [ "$N_VULN" -gt 0 ] || [ "$N_RESTART" -gt 0 ]; then
  RESULT=vulnerable; EXIT=1
elif [ "$N_ATTN" -gt 0 ] || [ "$N_IOC" -gt 0 ]; then
  RESULT=attention; EXIT=2
elif [ ${#R_PATH[@]} -eq 0 ]; then
  RESULT=no_php_found; EXIT=3
else
  RESULT=ok; EXIT=0
fi

HOST=$(hostname 2>/dev/null || echo unknown)
OS=$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || uname -sr)

# ---------------------------------------------------------------- output ---

if [ "$OUT_JSON" -eq 1 ]; then
  printf '{\n'
  printf '  "tool": "php2shell-hostcheck",\n  "version": "%s",\n  "data_date": "%s",\n' "$TOOL_VERSION" "$DATA_DATE"
  printf '  "cves": ["CVE-2026-109618", "CVE-2026-109619"],\n'
  printf '  "host": "%s",\n  "os": "%s",\n  "run_as_root": %s,\n' "$(json_esc "$HOST")" "$(json_esc "$OS")" "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)"
  printf '  "checked_at": "%s",\n' "$(date -u +%FT%TZ)"
  printf '  "result": "%s",\n  "exit_code": %d,\n' "$RESULT" "$EXIT"
  printf '  "runtimes": ['
  sep=""
  for i in "${!R_PATH[@]}"; do
    printf '%s\n    {"path": "%s", "kind": "%s", "version": "%s", "package": "%s", "status": "%s", "note": "%s", "ini": {"session.upload_progress.enabled": "%s", "post_max_size": "%s", "memory_limit": "%s", "fatal_error_backtraces": "%s"}}' \
      "$sep" "$(json_esc "${R_PATH[$i]}")" "${R_KIND[$i]}" "$(json_esc "${R_VER[$i]}")" "$(json_esc "${R_PKG[$i]}")" \
      "${R_STATUS[$i]}" "$(json_esc "${R_NOTE[$i]}")" "$(json_esc "${R_UP[$i]}")" "$(json_esc "${R_POST[$i]}")" \
      "$(json_esc "${R_MEM[$i]}")" "$(json_esc "${R_FEB[$i]}")"
    sep=","
  done
  [ -n "$sep" ] && printf '\n  '
  printf '],\n  "config_overrides": ['
  sep=""
  for o in "${OVERRIDES[@]}"; do printf '%s"%s"' "$sep" "$(json_esc "$o")"; sep=", "; done
  printf '],\n  "ioc_scanned": %s,\n  "ioc_since": "%s",\n  "ioc_roots": [' "$([ "$DO_IOC" -eq 1 ] && echo true || echo false)" "$SINCE"
  sep=""
  for r in "${IOC_ROOTS[@]}"; do printf '%s"%s"' "$sep" "$(json_esc "$r")"; sep=", "; done
  printf '],\n  "findings": ['
  sep=""
  for i in "${!F_SEV[@]}"; do
    printf '%s\n    {"severity": "%s", "title": "%s", "detail": "%s"}' "$sep" "${F_SEV[$i]}" "$(json_esc "${F_TITLE[$i]}")" "$(json_esc "${F_DETAIL[$i]}")"
    sep=","
  done
  [ -n "$sep" ] && printf '\n  '
  printf '],\n  "notes": ['
  sep=""
  for n in "${NOTES[@]}"; do printf '%s"%s"' "$sep" "$(json_esc "$n")"; sep=", "; done
  printf ']\n}\n'
  exit "$EXIT"
fi

status_tag() {
  case "$1" in
    PATCHED|PATCHED_BACKPORT) printf '%s[%s]%s' "$GRN" "$1" "$RST" ;;
    VULNERABLE|EOL) printf '%s%s[%s]%s' "$RED" "$BLD" "$1" "$RST" ;;
    *) printf '%s[%s]%s' "$YEL" "$1" "$RST" ;;
  esac
}
sev_tag() {
  case "$1" in
    high) printf '%s%s[HIGH]%s' "$RED" "$BLD" "$RST" ;;
    medium) printf '%s[MEDIUM]%s' "$YEL" "$RST" ;;
    *) printf '%s[INFO]%s' "$DIM" "$RST" ;;
  esac
}

echo "${BLD}php2shell-hostcheck $TOOL_VERSION${RST} — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)"
echo "${DIM}Host: $HOST | $OS | root: $([ "$IS_ROOT" -eq 1 ] && echo yes || echo no) | data: $DATA_DATE${RST}"
echo
echo "${BLD}PHP RUNTIMES${RST}"
if [ ${#R_PATH[@]} -eq 0 ]; then
  echo "  No PHP runtime found in the usual locations."
else
  for i in "${!R_PATH[@]}"; do
    printf '  %s %s  %s  %s%s\n' "$(status_tag "${R_STATUS[$i]}")" "${R_VER[$i]:-?}" "${R_KIND[$i]}" "${R_PATH[$i]}" \
      "$([ -n "${R_PKG[$i]}" ] && printf '  %s(%s)%s' "$DIM" "${R_PKG[$i]}" "$RST")"
    printf '      %s\n' "${R_NOTE[$i]}"
    if [ "${R_KIND[$i]}" != mod_php ]; then
      line="session.upload_progress.enabled=${R_UP[$i]}  post_max_size=${R_POST[$i]}  memory_limit=${R_MEM[$i]}"
      [ "${R_FEB[$i]}" != "n/a" ] && line="$line  fatal_error_backtraces=${R_FEB[$i]}"
      printf '      %s%s%s\n' "$DIM" "$line" "$RST"
    fi
  done
fi

if [ ${#OVERRIDES[@]} -gt 0 ]; then
  echo
  echo "${BLD}CONFIG OVERRIDES (FPM pools / Apache)${RST}"
  printf '  %s\n' "${OVERRIDES[@]}"
fi

if [ "$N_VULN" -gt 0 ]; then
  echo
  echo "${BLD}TEMPORARY MITIGATIONS (only if you cannot patch right now)${RST}"
  echo "  These reduce exposure but are NOT a fix. Patching is the only complete fix."
  echo "  - session.upload_progress.enabled = Off, then restart every PHP worker"
  echo "  - post_max_size = 8M (or 32M if the site needs uploads)"
  echo "  - PHP 8.5: fatal_error_backtraces = Off"
  echo "  - Set them as php_admin_value / php_admin_flag in the FPM pool so apps can't override them"
  echo "  - Put a WAF with PHP2Shell rules in front of the site"
fi

if [ ${#F_SEV[@]} -gt 0 ] || [ "$DO_IOC" -eq 1 ]; then
  echo
  if [ "$DO_IOC" -eq 1 ]; then
    echo "${BLD}FINDINGS${RST} ${DIM}(indicators since $SINCE; roots: ${IOC_ROOTS[*]:-none})${RST}"
  else
    echo "${BLD}FINDINGS${RST}"
  fi
  if [ ${#F_SEV[@]} -eq 0 ]; then
    echo "  Nothing flagged."
  else
    for i in "${!F_SEV[@]}"; do
      printf '  %s %s\n' "$(sev_tag "${F_SEV[$i]}")" "${F_TITLE[$i]}"
      printf '%s\n' "${F_DETAIL[$i]}" | sed 's/^/    /'
    done
  fi
fi

if [ ${#NOTES[@]} -gt 0 ]; then
  echo
  echo "${BLD}NOTES${RST}"
  for n in "${NOTES[@]}"; do printf '  - %s\n' "$n"; done
fi

echo
case "$RESULT" in
  vulnerable) echo "${RED}${BLD}RESULT: VULNERABLE${RST} — patch/upgrade PHP and restart PHP-FPM / the web server." ;;
  attention)  echo "${YEL}${BLD}RESULT: NEEDS ATTENTION${RST} — review the items above." ;;
  no_php_found) echo "${YEL}${BLD}RESULT: NO PHP FOUND${RST} — if this host serves PHP, check containers or custom paths." ;;
  ok) echo "${GRN}${BLD}RESULT: OK${RST} — every PHP runtime found is patched." ;;
esac
if [ "$DO_IOC" -eq 0 ]; then
  echo "${DIM}Exploitation started before the patch. Run again with --ioc to look for signs of compromise.${RST}"
fi
echo "${DIM}Indicator check only — a clean result is not proof the host is safe or uncompromised.${RST}"
exit "$EXIT"
