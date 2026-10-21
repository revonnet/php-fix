#!/usr/bin/env bash
# php-fix: Emergency mitigation for php2shell (CVE-2026-109618 / CVE-2026-109619)
# Sets session.upload_progress.enabled = Off across all PHP installations on the host.
#
# Author: Revonnet EOOD
# Website: https://revon.net
# Repository: https://github.com/revonnet/php-fix
# License: MIT
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/revonnet/php-fix/main/install.sh | sudo bash
#   curl -fsSL .../install.sh | sudo bash -s -- --dry-run      # show what would change, change nothing
#   curl -fsSL .../install.sh | sudo bash -s -- --no-restart   # do not reload PHP / web services
#   curl -fsSL .../install.sh | sudo bash -s -- --force-reload # reload services even if configs are already fixed
#
# IMPORTANT: This is an emergency stopgap mitigation.
# The only permanent resolution is upgrading PHP to the officially patched vendor release.

set -u

DIRECTIVE="session.upload_progress.enabled"
TS="$(date +%Y%m%d-%H%M%S)"
DRY_RUN=0
NO_RESTART=0
FORCE_RELOAD=0

for arg in "$@"; do
  case "$arg" in
    --dry-run)
      DRY_RUN=1
      ;;
    --no-restart)
      NO_RESTART=1
      ;;
    -f|--force-reload|--force-restart)
      FORCE_RELOAD=1
      ;;
    -h|--help)
      echo "php-fix: Emergency mitigation for php2shell (CVE-2026-109618 / CVE-2026-109619)"
      echo "Author: Revonnet EOOD (https://revon.net)"
      echo
      echo "Usage: $0 [OPTIONS]"
      echo
      echo "Options:"
      echo "  --dry-run         Show what changes would be made without modifying any file or reloading services"
      echo "  --no-restart      Update configuration files but do not reload PHP-FPM or web server services"
      echo "  -f, --force-reload"
      echo "                    Force reload of PHP-FPM/web services even if configuration files were already updated"
      echo "  -h, --help        Show this help message and exit"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg"
      echo "Use '$0 --help' for usage."
      exit 1
      ;;
  esac
done

if [ -t 1 ]; then
  G='\033[0;32m'
  Y='\033[1;33m'
  R='\033[0;31m'
  N='\033[0m'
else
  G=''
  Y=''
  R=''
  N=''
fi

ok()   { printf "%b[OK]%b %s\n" "$G" "$N" "$*"; }
info() { printf "%b[..]%b %s\n" "$Y" "$N" "$*"; }
err()  { printf "%b[!!]%b %s\n" "$R" "$N" "$*"; }

if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  err "Run as root: curl -fsSL ... | sudo bash"
  exit 1
fi

# Portable realpath/readlink helper
canonicalize_path() {
  local p="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$p" 2>/dev/null || echo "$p"
  elif readlink -f "$p" >/dev/null 2>&1; then
    readlink -f "$p" 2>/dev/null || echo "$p"
  else
    echo "$p"
  fi
}

# Portable in-place sed helper (supports GNU sed and BSD/macOS sed)
sed_inplace() {
  if sed --version >/dev/null 2>&1; then
    sed -i -E "$@"
  else
    sed -i "" -E "$@"
  fi
}

# Verify directory is root-owned and not group/world writable
is_safe_dir() {
  local dir="$1"
  local uid mode

  # Check owner UID (0 = root)
  uid="$(stat -c %u "$dir" 2>/dev/null || stat -f %u "$dir" 2>/dev/null)"
  if [ "$uid" != "0" ]; then
    return 1
  fi

  # Check permissions (must not have group-write or world-write bits)
  mode="$(stat -c %a "$dir" 2>/dev/null || stat -f %Lp "$dir" 2>/dev/null)"
  if [ -n "$mode" ]; then
    if [ "$(( 8#$mode & 8#022 ))" -ne 0 ]; then
      return 1
    fi
  else
    if [ -n "$(find "$dir" -maxdepth 0 \( -perm -020 -o -perm -002 \) 2>/dev/null)" ]; then
      return 1
    fi
  fi
  return 0
}

# Safely back up files preventing symlink traversal or unsafe directories
backup() {
  local src="$1"
  local dir dst="$src.bak-$TS"
  dir="$(dirname "$src")"

  if ! is_safe_dir "$dir"; then
    err "Unsafe directory (not root-owned or group/world-writable), skipping: $dir"
    return 1
  fi

  if [ -e "$dst" ] || [ -L "$dst" ]; then
    err "Backup path already exists: $dst"
    return 1
  fi

  # Portable copy preserving attributes without dereferencing symlinks
  cp -P -p "$src" "$dst"
}

# Known PHP locations across Linux distributions, control panels, and BSD/macOS
SEARCH_ROOTS=(
  /etc
  /usr/local/etc
  /usr/local/lib
  /usr/local/php*
  /opt/cpanel
  /opt/alt
  /opt/plesk/php
  /opt/remi
  /etc/opt/remi
  /opt/rh
  /opt/lampp
  /opt/homebrew/etc
  /www/server/php
  /usr/local/lsws
)

existing_roots=()
for r in "${SEARCH_ROOTS[@]}"; do
  for dir in $r; do
    if [ -d "$dir" ]; then
      existing_roots+=("$dir")
    fi
  done
done

ACTIVE_RE="^[[:space:]]*${DIRECTIVE//./\\.}[[:space:]]*="
ANY_RE="^[[:space:]]*;?[[:space:]]*${DIRECTIVE//./\\.}[[:space:]]*="
OFF_RE="^[[:space:]]*${DIRECTIVE//./\\.}[[:space:]]*=[[:space:]]*\"?(off|0|false|no|none)?\"?[[:space:]]*(;.*)?$"
POOL_RE="php_(admin_)?(value|flag)\[${DIRECTIVE//./\\.}\]"
POOL_OFF_RE="^[[:space:]]*${POOL_RE}[[:space:]]*=[[:space:]]*\"?(off|0|false|no|none)?\"?[[:space:]]*(;.*)?$"

CHANGED=0
SKIPPED=0
FAILED=0

# Helper to find all candidate php.ini files
find_all_ini() {
  if [ ${#existing_roots[@]} -gt 0 ]; then
    find "${existing_roots[@]}" -xdev -type f -name 'php.ini' 2>/dev/null
  fi
  if command -v php >/dev/null 2>&1; then
    php -r 'echo php_ini_loaded_file()."\n";' 2>/dev/null
    php --ini 2>/dev/null | awk -F': *' '/Loaded Configuration File/ { gsub(/["[:space:]]/, "", $2); if ($2 != "" && $2 != "(none)") print $2 }'
  fi
}

# 1) Collect and canonicalize php.ini files
INI_FILES=()
while IFS= read -r f || [ -n "$f" ]; do
  if [ -f "$f" ]; then
    cf="$(canonicalize_path "$f")"
    [ -n "$cf" ] && INI_FILES+=("$cf")
  fi
done < <(find_all_ini | grep -v '(none)' | sort -u)

# Deduplicate INI_FILES array
if [ ${#INI_FILES[@]} -gt 0 ]; then
  mapfile_dedup=()
  while IFS= read -r f || [ -n "$f" ]; do
    [ -n "$f" ] && mapfile_dedup+=("$f")
  done < <(printf "%s\n" "${INI_FILES[@]}" | sort -u)
  INI_FILES=("${mapfile_dedup[@]}")
fi

if [ ${#INI_FILES[@]} -eq 0 ]; then
  err "No php.ini found on system."
  exit 1
fi

info "Found ${#INI_FILES[@]} php.ini file(s)."

# Also register parent directories of discovered php.ini files for conf.d / pool scans
for f in "${INI_FILES[@]}"; do
  f_dir="$(dirname "$f")"
  [ -d "$f_dir" ] && existing_roots+=("$f_dir")
  p_dir="$(dirname "$f_dir")"
  [ -d "$p_dir" ] && existing_roots+=("$p_dir")
done

# Deduplicate existing_roots
if [ ${#existing_roots[@]} -gt 0 ]; then
  roots_dedup=()
  while IFS= read -r r || [ -n "$r" ]; do
    [ -n "$r" ] && roots_dedup+=("$r")
  done < <(printf "%s\n" "${existing_roots[@]}" | sort -u)
  existing_roots=("${roots_dedup[@]}")
fi

for f in "${INI_FILES[@]}"; do
  active_lines="$(grep -Ei "$ACTIVE_RE" "$f" || true)"
  if [ -n "$active_lines" ] && ! echo "$active_lines" | grep -Eivq "$OFF_RE"; then
    ok "Already Off: $f"
    SKIPPED=$((SKIPPED+1))
    continue
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    info "[dry-run] Would change: $f"
    continue
  fi

  if ! backup "$f"; then
    err "Backup failed: $f"
    FAILED=$((FAILED+1))
    continue
  fi

  if grep -Eiq "$ANY_RE" "$f"; then
    # Replace existing (commented or active) directive
    sed_inplace "s/${ANY_RE}.*/${DIRECTIVE} = Off/I" "$f"
  elif grep -Eiq '^[[:space:]]*\[Session\]' "$f"; then
    # Insert right below the [Session] section header
    sed_inplace "s|^([[:space:]]*\[Session\].*)|\\1\n${DIRECTIVE} = Off|I" "$f"
  else
    # Append a new [Session] section
    printf '\n[Session]\n%s = Off\n' "$DIRECTIVE" >> "$f"
  fi

  if grep -Eiq "$OFF_RE" "$f"; then
    ok "Updated: $f  (backup: $f.bak-$TS)"
    CHANGED=$((CHANGED+1))
  else
    err "Could not update: $f"
    FAILED=$((FAILED+1))
  fi
done

if [ ${#existing_roots[@]} -gt 0 ]; then
  # 2) Extra .ini files (conf.d etc.) that might re-enable upload progress
  EXTRA_INI=()
  while IFS= read -r f || [ -n "$f" ]; do
    if [ -f "$f" ]; then
      cf="$(canonicalize_path "$f")"
      [ -n "$cf" ] && EXTRA_INI+=("$cf")
    fi
  done < <(
    find "${existing_roots[@]}" -xdev -type f -name '*.ini' ! -name 'php.ini' \
      -exec grep -Eil "$ACTIVE_RE" {} + 2>/dev/null | sort -u
  )

  # Deduplicate EXTRA_INI
  if [ ${#EXTRA_INI[@]} -gt 0 ]; then
    extra_dedup=()
    while IFS= read -r f || [ -n "$f" ]; do
      [ -n "$f" ] && extra_dedup+=("$f")
    done < <(printf "%s\n" "${EXTRA_INI[@]}" | sort -u)
    EXTRA_INI=("${extra_dedup[@]}")
  fi

  for f in ${EXTRA_INI[@]+"${EXTRA_INI[@]}"}; do
    # Skip if not actively turning it On
    if ! grep -Ei "$ACTIVE_RE" "$f" | grep -Eivq "$OFF_RE"; then
      continue
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
      info "[dry-run] Would fix override: $f"
      continue
    fi

    if backup "$f" && sed_inplace "s/${ACTIVE_RE}.*/${DIRECTIVE} = Off/I" "$f"; then
      ok "Fixed override: $f  (backup: $f.bak-$TS)"
      CHANGED=$((CHANGED+1))
    else
      err "Could not fix override: $f"
      FAILED=$((FAILED+1))
    fi
  done

  # 3) PHP-FPM pool php_value/php_flag overrides -> enforce php_admin_flag off
  POOL_FILES=()
  while IFS= read -r f || [ -n "$f" ]; do
    if [ -f "$f" ]; then
      cf="$(canonicalize_path "$f")"
      [ -n "$cf" ] && POOL_FILES+=("$cf")
    fi
  done < <(
    find "${existing_roots[@]}" -xdev -type f -name '*.conf' \
      -exec grep -Eil "^[[:space:]]*${POOL_RE}" {} + 2>/dev/null | sort -u
  )

  # Deduplicate POOL_FILES
  if [ ${#POOL_FILES[@]} -gt 0 ]; then
    pool_dedup=()
    while IFS= read -r f || [ -n "$f" ]; do
      [ -n "$f" ] && pool_dedup+=("$f")
    done < <(printf "%s\n" "${POOL_FILES[@]}" | sort -u)
    POOL_FILES=("${pool_dedup[@]}")
  fi

  for f in ${POOL_FILES[@]+"${POOL_FILES[@]}"}; do
    if ! grep -Ei "^[[:space:]]*${POOL_RE}" "$f" | grep -Eivq "$POOL_OFF_RE" \
       && ! grep -Eiq "^[[:space:]]*php_(value|flag)\[${DIRECTIVE//./\\.}\]" "$f"; then
      continue  # Already hardened with php_admin_flag ... = off
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
      info "[dry-run] Would fix FPM pool: $f"
      continue
    fi

    if backup "$f" && sed_inplace "s/^([[:space:]]*)(${POOL_RE})[[:space:]]*=.*/\\1php_admin_flag[${DIRECTIVE}] = off/I" "$f"; then
      ok "Fixed FPM pool: $f  (backup: $f.bak-$TS)"
      CHANGED=$((CHANGED+1))
    else
      err "Could not fix FPM pool: $f"
      FAILED=$((FAILED+1))
    fi
  done
fi

# 4) Reload services
if [ "$DRY_RUN" -eq 0 ] && [ "$NO_RESTART" -eq 0 ] && { [ "$CHANGED" -gt 0 ] || [ "$FORCE_RELOAD" -eq 1 ]; }; then
  info "Reloading PHP / web services..."

  if command -v systemctl >/dev/null 2>&1; then
    SVCS=()
    while IFS= read -r s || [ -n "$s" ]; do
      [ -n "$s" ] && SVCS+=("$s")
    done < <(
      systemctl list-units --type=service --no-legend 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i ~ /\.service$/){print $i;break}}' \
        | grep -Ei '^(php.*fpm|ea-php.*|rh-php.*fpm|plesk-php.*|apache2|httpd|lsws|lshttpd|litespeed|openlitespeed)\.service$' \
        | sort -u
    )
    for s in ${SVCS[@]+"${SVCS[@]}"}; do
      if systemctl reload-or-restart "$s" >/dev/null 2>&1; then
        ok "Reloaded: $s"
      else
        err "Could not reload: $s"
      fi
    done
  elif command -v rc-service >/dev/null 2>&1; then
    # Alpine Linux / OpenRC
    for s in $(rc-status -s 2>/dev/null | awk '{print $1}' | grep -Ei '^(php.*fpm|apache2|httpd|nginx)$'); do
      if rc-service "$s" restart >/dev/null 2>&1; then
        ok "Restarted: $s"
      fi
    done
  elif command -v service >/dev/null 2>&1; then
    # SysV init fallback
    for init_script in /etc/init.d/php*-fpm /etc/init.d/apache2 /etc/init.d/httpd; do
      if [ -x "$init_script" ]; then
        s="$(basename "$init_script")"
        if service "$s" reload >/dev/null 2>&1 || service "$s" restart >/dev/null 2>&1; then
          ok "Reloaded: $s"
        fi
      fi
    done
  fi

  # LiteSpeed lsphp worker processes
  if pkill -f lsphp >/dev/null 2>&1; then
    ok "Killed lsphp processes (LiteSpeed will respawn them)"
  fi
fi

# 5) Verification via CLI binaries
info "Verification:"

collect_php_bins() {
  local p
  command -v php 2>/dev/null
  command -v lsphp 2>/dev/null
  for p in \
    /usr/bin/php \
    /usr/bin/php[0-9]* \
    /usr/bin/php-[0-9]* \
    /usr/local/bin/php \
    /usr/local/bin/php[0-9]* \
    /opt/homebrew/bin/php \
    /opt/homebrew/bin/php@* \
    /opt/lampp/bin/php \
    /opt/cpanel/ea-php*/root/usr/bin/php \
    /opt/alt/php*/usr/bin/php \
    /opt/plesk/php/*/bin/php \
    /www/server/php/*/bin/php \
    /usr/local/php*/bin/php \
    /opt/remi/php*/root/usr/bin/php \
    /opt/rh/rh-php*/root/usr/bin/php \
    /usr/local/lsws/lsphp*/bin/php \
    /usr/local/lsws/bin/lsphp*; do
      if [ -x "$p" ]; then
        canonicalize_path "$p"
      fi
  done
}

PHP_BINS=()
while IFS= read -r b || [ -n "$b" ]; do
  if [ -x "$b" ]; then
    case "$(basename "$b")" in
      php|php[0-9]*|php-[0-9]*|lsphp*)
        PHP_BINS+=("$b")
        ;;
      *)
        ;;
    esac
  fi
done < <(collect_php_bins | sort -u)

# Deduplicate PHP_BINS
if [ ${#PHP_BINS[@]} -gt 0 ]; then
  bins_dedup=()
  while IFS= read -r b || [ -n "$b" ]; do
    [ -n "$b" ] && bins_dedup+=("$b")
  done < <(printf "%s\n" "${PHP_BINS[@]}" | sort -u)
  PHP_BINS=("${bins_dedup[@]}")
fi

if [ ${#PHP_BINS[@]} -eq 0 ]; then
  info "No PHP CLI binaries found for direct verification."
else
  for b in "${PHP_BINS[@]}"; do
    ver="$("$b" -r 'echo PHP_VERSION;' 2>/dev/null)" || continue
    v="$("$b" -r "echo ini_get('${DIRECTIVE}');" 2>/dev/null)"
    if [ -z "$v" ] || [ "$v" = "0" ]; then
      ok "$b ($ver): Off"
    else
      err "$b ($ver): STILL ON ($v)"
      FAILED=$((FAILED+1))
    fi
  done
fi

echo
echo "Changed: $CHANGED | Already Off: $SKIPPED | Errors: $FAILED"

if [ "$DRY_RUN" -eq 1 ]; then
  info "Dry run finished, nothing was changed."
elif [ "$FAILED" -eq 0 ]; then
  printf "%bDONE ✔ %s = Off%b\n" "$G" "$DIRECTIVE" "$N"
  echo "Reminder: This is a stopgap mitigation. Upgrade PHP to the patched release as soon as possible."
else
  err "Some steps failed, check the output above."
  exit 1
fi
