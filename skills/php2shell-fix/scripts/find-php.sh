#!/usr/bin/env bash
# Find every PHP on this Linux host and report its PHP2Shell status.
# Read-only. Exit code: 0 = everything found is PATCHED, 2 = something needs action.
#
#   bash find-php.sh

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CHECK="$HERE/check.php"
CVES='CVE-2026-109618|CVE-2026-109619'
needs_action=0

say()  { printf '%s\n' "$*"; }
head1(){ printf '\n== %s ==\n' "$*"; }

# --- 1. collect candidate binaries ------------------------------------------
candidates=$(
  {
    command -v php php-fpm php-cgi lsphp 2>/dev/null
    ls -1 /usr/bin/php* /usr/local/bin/php* /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* \
          /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
          /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
          /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm \
          /opt/alt/php*/usr/bin/php /usr/local/lsws/lsphp*/bin/lsphp \
          /usr/local/php*/bin/php /usr/local/php*/sbin/php-fpm 2>/dev/null
  } | while read -r p; do
        case "$(basename "$p")" in
          php|php[0-9]*|php-fpm|php-fpm[0-9]*|php-cgi|php-cgi[0-9]*|lsphp) ;;
          *) continue ;;
        esac
        [ -x "$p" ] && readlink -f "$p"
      done | sort -u
)

# The first CLI php we find is used to run check.php for every verdict.
runner=""
for p in $candidates; do
  case "$(basename "$p")" in php|php[0-9]*) runner="$p"; break ;; esac
done

verdict_for() {
  if [ -n "$runner" ]; then
    "$runner" "$CHECK" --verdict="$1" 2>/dev/null || echo UNKNOWN
  else
    echo "UNKNOWN (no php CLI to run check.php)"
  fi
}

# --- 2. version + verdict per binary ----------------------------------------
head1 "PHP binaries"
if [ -z "$candidates" ]; then
  say "No PHP binaries found in standard locations."
fi
for p in $candidates; do
  ver=$("$p" -v 2>/dev/null | head -1 | awk '{print $2}')
  [ -z "$ver" ] && ver="?"
  v=$(verdict_for "$ver")
  printf '%-14s %-28s %s\n' "$v" "$ver" "$p"
  case "$v" in PATCHED*) ;; *) needs_action=1 ;; esac
done

# --- 3. running FPM masters (these serve traffic right now) -----------------
head1 "Running PHP-FPM masters"
ps -eo pid=,args= 2>/dev/null | grep -E 'php-fpm: master|php[0-9.]*-fpm: master' | grep -v grep \
  || say "none"

# --- 4. Apache mod_php ------------------------------------------------------
head1 "Apache mod_php (most urgent if present)"
mods=""
for ctl in apachectl apache2ctl httpd; do
  if command -v "$ctl" >/dev/null 2>&1; then
    mods=$("$ctl" -M 2>/dev/null | grep -i php)
    [ -n "$mods" ] && break
  fi
done
if [ -n "$mods" ]; then
  say "$mods"
  say "mod_php is loaded. Its version may differ from 'php -v':"
  say "check it through the web server with check.php (SKILL.md step 3)."
  needs_action=1
else
  say "not loaded (or Apache not found)"
fi

# --- 5. distro backports: look for the CVE IDs in package changelogs --------
head1 "Distro package changelogs mentioning $CVES"
found_pkg=0
for f in /usr/share/doc/php*-common/changelog.Debian.gz; do
  [ -f "$f" ] || continue
  found_pkg=1
  if zgrep -qE "$CVES" "$f" 2>/dev/null; then
    say "PATCHED  $(basename "$(dirname "$f")") (fix listed in changelog)"
  else
    say "NOT LISTED  $(basename "$(dirname "$f")") (no fix in changelog: update this package)"
  fi
done
if command -v rpm >/dev/null 2>&1; then
  for pkg in $(rpm -qa 2>/dev/null | grep -E '^(php|php[0-9]+|ea-php[0-9]+|alt-php[0-9]+)(-php)?-common' ); do
    found_pkg=1
    if rpm -q --changelog "$pkg" 2>/dev/null | grep -qE "$CVES"; then
      say "PATCHED  $pkg (fix listed in changelog)"
    else
      say "NOT LISTED  $pkg (no fix in changelog: update or check vendor advisory)"
    fi
  done
fi
[ "$found_pkg" -eq 0 ] && say "no Debian/Ubuntu or RPM PHP packages found"

# --- 6. Docker containers ---------------------------------------------------
if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
  head1 "Running Docker containers with PHP"
  docker ps --format '{{.Names}} {{.Image}}' | while read -r name image; do
    ver=$(docker exec "$name" php -r 'echo PHP_VERSION;' 2>/dev/null) || continue
    printf '%-14s %-28s container=%s image=%s\n' "$(verdict_for "$ver")" "$ver" "$name" "$image"
  done
fi

head1 "Summary"
if [ "$needs_action" -eq 0 ]; then
  say "All PHP binaries found report PATCHED. Still run check.php through the web server to be sure."
  exit 0
fi
say "Action needed: see SKILL.md step 4 for what each verdict means."
exit 2
