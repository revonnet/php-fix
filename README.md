# php-fix

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-Passing-brightgreen.svg)](https://www.shellcheck.net/)
[![Bash](https://img.shields.io/badge/Bash-3.2%2B-lightgrey.svg)](https://www.gnu.org/software/bash/)
[![Security: php2shell](https://img.shields.io/badge/Mitigation-CVE--2026--109618%20%2F%20109619-red.svg)](https://www.php.net/)
[![Author: Revonnet EOOD](https://img.shields.io/badge/Maintainer-Revonnet%20EOOD-blueviolet.svg)](https://revon.net)

One-line emergency mitigation for **php2shell** (**CVE-2026-109618** / **CVE-2026-109619**), the critical PHP Remote Code Execution vulnerabilities (CVSS v4.0 **9.2**) affecting PHP environments processing multipart form data.

This automated utility enforces `session.upload_progress.enabled = Off` across all installed PHP instances on a host—supporting standard Linux distributions, multi-PHP installations, control panels, and containers.

> [!IMPORTANT]
> **Emergency Stopgap Mitigation:** Disabling `session.upload_progress.enabled` closes the unauthenticated use-after-free (UAF) exploit path within PHP's session upload progress mechanism. However, **the only permanent resolution is upgrading PHP to the officially patched vendor release** once your distribution, vendor, or control panel provides updated packages.

---

## Quick Start

Run the automated mitigation directly as root:

```bash
curl -fsSL https://raw.githubusercontent.com/revonnet/php-fix/main/install.sh | sudo bash
```

### Preview changes first (Dry Run)

Inspect all detected configuration files and planned changes without touching any files or restarting services:

```bash
curl -fsSL https://raw.githubusercontent.com/revonnet/php-fix/main/install.sh | sudo bash -s -- --dry-run
```

### Apply without restarting services

Apply configuration fixes immediately while deferring web service / PHP-FPM restarts for a scheduled maintenance window:

```bash
curl -fsSL https://raw.githubusercontent.com/revonnet/php-fix/main/install.sh | sudo bash -s -- --no-restart
```

### Force service reload

Reload web services and PHP-FPM pools even if configuration files were already patched in a previous run:

```bash
curl -fsSL https://raw.githubusercontent.com/revonnet/php-fix/main/install.sh | sudo bash -s -- --force-reload
```

### Inspect the script before executing

As a security best practice, review the script locally before running with root privileges:

```bash
curl -fsSLO https://raw.githubusercontent.com/revonnet/php-fix/main/install.sh
less install.sh
sudo bash install.sh
```

---

## What the Script Does

1. **Exhaustive PHP Configuration Discovery:** Scans standard system paths (`/etc`, `/usr/local/etc`, `/usr/local/lib`), software collections, vendor directories, control panels (`cPanel`, `Plesk`, `CloudLinux`, `aaPanel`, `DirectAdmin`, `LiteSpeed`, `Remi`, `Homebrew`), and resolves runtime active paths via PHP CLI.
2. **Automated INI Enforcement:** Sets `session.upload_progress.enabled = Off` in each detected `php.ini`. Updates active lines, uncomments inactive directives, inserts into `[Session]` blocks, or appends a new `[Session]` section if missing.
3. **Override Neutralization:** Recursively scans additional configuration directories (`conf.d/*.ini`, `*.ini`) to ensure no secondary configuration file turns the setting back `On`.
4. **PHP-FPM Pool Hardening:** Converts any `php_value` or `php_flag` directives for upload progress inside pool configurations (`*.conf`) into `php_admin_flag[session.upload_progress.enabled] = off`, preventing individual virtual hosts or applications from overriding the safeguard via `.user.ini` or `.htaccess`.
5. **Intelligent Service Reloading:** Detects and reloads active PHP-FPM daemons, Apache/httpd, LiteSpeed (`lsws`, `openlitespeed`), kills active `lsphp` workers to force configuration re-read, and supports systemd, OpenRC, and SysV init environments.
6. **Multi-Binary Verification:** Runs verification checks across every PHP CLI runtime binary discovered on the server and displays a comprehensive status report.
7. **Safe, Timestamped Backups:** Before modifying any configuration file, creates a non-dereferencing timestamped backup next to the file (`<file>.bak-YYYYMMDD-HHMMSS`) with strict directory safety validation (blocking symlink planting attacks).

---

## Supported Environments

| Distribution / Environment | Configuration Paths Covered | Service Handlers |
|---|---|---|
| **Debian / Ubuntu** (Standard & ondrej/php PPA) | `/etc/php/*/{fpm,cli,apache2}/php.ini`, `/etc/php/*/conf.d/*.ini` | `systemd`, `service` |
| **RHEL / Rocky / AlmaLinux / CentOS** | `/etc/php.ini`, `/etc/php.d/*.ini`, `/etc/opt/remi/*`, `/opt/remi/*`, `/opt/rh/rh-php*` | `systemd` |
| **cPanel & WHM** (EasyApache 4) | `/opt/cpanel/ea-php*/root/etc/php.ini`, `/opt/cpanel/ea-php*/root/etc/php.d/` | `ea-php*-php-fpm`, `httpd` |
| **CloudLinux** (alt-php) | `/opt/alt/php*/etc/php.ini`, `/opt/alt/php*/etc/php.d/` | `alt-php*-fpm` |
| **Plesk** | `/opt/plesk/php/*/etc/php.ini`, `/opt/plesk/php/*/etc/php.d/` | `plesk-php*-fpm` |
| **aaPanel / BT Panel** | `/www/server/php/*/etc/php.ini` | `php-fpm`, `nginx`, `httpd` |
| **DirectAdmin / CustomBuild** | `/usr/local/php*`, `/usr/local/lib/php.ini` | `php-fpm*`, `httpd` |
| **LiteSpeed / OpenLiteSpeed** | `/usr/local/lsws/lsphp*/etc/php/*/litespeed/php.ini`, `/usr/local/lsws/conf/` | `lsws`, `lshttpd`, `lsphp` worker reload |
| **Alpine Linux / Containers** | `/etc/php*`, `/usr/local/etc/php` | `rc-service` (OpenRC) |
| **macOS / Linuxbrew (Homebrew)** | `/opt/homebrew/etc/php/*`, `/usr/local/etc/php/*` | CLI verification |

---

## Side Effects & Impact Analysis

- **Standard File Uploads:** Normal file uploads through HTML forms (`multipart/form-data`) and `$_FILES` **continue to function completely normally**.
- **Upload Progress Tracking:** Disabling this directive only stops PHP from writing real-time upload byte counts to `$_SESSION['upload_progress_*']`. Only legacy web applications that poll session variables to render progress bars will experience degraded progress bars (the upload itself will still succeed).
- **Idempotent:** Safe to run repeatedly. Files that are already configured with `session.upload_progress.enabled = Off` are automatically detected and skipped.

---

## Verification

### CLI Verification

Verify the directive status on your default CLI binary:

```bash
php -i | grep -i "session.upload_progress.enabled"
# Expected output:
# session.upload_progress.enabled => Off => Off
```

Or query the directive directly:

```bash
php -r "echo ini_get('session.upload_progress.enabled') ? 'VULNERABLE (On)' : 'PROTECTED (Off)';"
```

### Web SAPI / PHP-FPM Verification

Create a temporary test script inside your document root:

```php
<?php
// test-progress.php
header('Content-Type: text/plain');
$val = ini_get('session.upload_progress.enabled');
echo ($val === '' || $val === '0' || strtolower($val) === 'off') ? "PROTECTED (Off)\n" : "VULNERABLE (On)\n";
```

Access the script via browser or `curl`, confirm output is `PROTECTED (Off)`, and **immediately remove the test file**:

```bash
rm -f test-progress.php
```

---

## Out-of-Scope Items (Manual Checks)

- **Application Document Roots (`.user.ini` / `.htaccess`):**
  If PHP-FPM pools are hardened using `php_admin_flag` (which this script enforces), users cannot re-enable the directive via `.user.ini`. However, on Apache `mod_php` deployments without admin flag overrides, a site might attempt to set `php_flag session.upload_progress.enabled on`. Check web roots with:
  ```bash
  grep -rEil 'session\.upload_progress\.enabled' /var/www /home --include=.htaccess --include=.user.ini 2>/dev/null
  ```
- **Docker Containers:**
  Container instances should have their base images updated or append a configuration drop-in during container build:
  ```dockerfile
  RUN echo "session.upload_progress.enabled = Off" > /usr/local/etc/php/conf.d/zz-security-php2shell.ini
  ```
- **Reverse Proxy / WAF Filtering:**
  If uploads are not required for your public endpoints, consider blocking or filtering `multipart/form-data` requests at your WAF (Cloudflare, ModSecurity, AWS WAF, or Nginx reverse proxy) until full vendor patches are applied.

---

## Rollback & Recovery

Every file modified by the script is backed up with a timestamped extension (`.bak-YYYYMMDD-HHMMSS`).

To list all backups created by this tool:

```bash
find /etc /opt /usr/local /www -type f -name '*bak-2026*' 2>/dev/null
```

To restore an original configuration:

```bash
cp -P -p /etc/php/8.3/fpm/php.ini.bak-20261021-110000 /etc/php/8.3/fpm/php.ini
systemctl reload php8.3-fpm
```

---

## Vulnerability Information & References

- **CVE Identifiers:** CVE-2026-109618, CVE-2026-109619
- **Severity Rating:** Critical — CVSS v4.0: 9.2 / CVSS v3.1: 9.8
- **PHP Official Security Portal:** [https://www.php.net/](https://www.php.net/)
- **SecureLayer7 Technical Analysis:** [php2shell Overview](https://blog.securelayer7.net/php-rce-cve-2026-109618-109619/)
- **Lilting Security Research:** [Disabling session.upload_progress UAF vector](https://lilting.ch/en/articles/php2shell-session-upload-progress-uaf)
- **Syhunt Defense-in-Depth Toolkit:** [Apache-level multipart filtering](https://github.com/syhunt/php2shell-protection)

---

## Author & Maintainer

Developed and maintained by [**Revonnet EOOD**](https://revon.net).

* **Website:** [https://revon.net](https://revon.net)
* **GitHub:** [https://github.com/revonnet](https://github.com/revonnet)

Contributions, bug reports, and pull requests are welcome on GitHub.

## License

This project is licensed under the [MIT License](LICENSE).
