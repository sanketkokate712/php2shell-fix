# Upgrading PHP for PHP2Shell, by platform

Target versions: **8.5.12, 8.4.27, 8.3.36 or 8.2.35** or newer. A distro package with the CVE IDs in its changelog is also fine.

After **any** upgrade, restart PHP-FPM and the web server, then run `check.php` through the web server again. Workers that are still running keep the old code in memory.

Back up config files first. If moving to a new minor branch (for example 7.4 to 8.3), test the site on a staging copy.

---

## Ubuntu / Debian: distro packages

```bash
sudo apt update
apt list --upgradable 2>/dev/null | grep -i php
sudo apt install --only-upgrade 'php*'
sudo systemctl restart 'php*-fpm' apache2 2>/dev/null; sudo systemctl restart nginx 2>/dev/null
```

Ubuntu and Debian backport fixes, so the version can stay at, say, `8.1.2-1ubuntu2.x`. Confirm the fix with:

```bash
zgrep -E 'CVE-2026-10961[89]' /usr/share/doc/php*-common/changelog.Debian.gz
```

No match means your release hasn't shipped the fix yet. Check the Ubuntu Security Notices (USN) or Debian Security Advisories (DSA), or switch to the Ondřej Surý repository below.

## Ubuntu / Debian: Ondřej Surý PPA or packages.sury.org

```bash
sudo apt update
sudo apt install --only-upgrade 'php8.3*'      # use your branch
php8.3 -v
sudo systemctl restart php8.3-fpm
```

## RHEL / AlmaLinux / Rocky / Fedora / Amazon Linux

```bash
sudo dnf upgrade --refresh 'php*'
rpm -q --changelog php-common | grep -E 'CVE-2026-10961[89]'
sudo systemctl restart php-fpm httpd
```

**Remi repository** (`php83-php-*` or module streams): `sudo dnf upgrade 'php*'`, then restart `php83-php-fpm`.

## Alpine (common in Docker)

```bash
apk update && apk upgrade 'php*'
```

## Docker

The official images are patched upstream. Rebuild; restarting isn't enough.

```dockerfile
FROM php:8.3.36-fpm      # pin the fixed patch release, or newer
```

```bash
docker compose pull && docker compose build --pull && docker compose up -d
```

Also rebuild any image based on `wordpress:`, `drupal:`, `nextcloud:` and similar images, once those images ship the fixed PHP.

## cPanel / WHM (EasyApache 4)

```bash
sudo dnf upgrade 'ea-php*'      # or: yum update 'ea-php*'
sudo /scripts/restartsrv_apache_php_fpm
```

In WHM, open **MultiPHP Manager** and move every domain still on ea-php74/80/81 or older to a supported version. **CloudLinux** `alt-php`: `sudo dnf upgrade 'alt-php*'`.

## Plesk

```bash
sudo plesk installer --select-release-current --upgrade-installed-components
```

Or use **Tools & Settings → Updates**. Then check each domain's PHP version under **Websites & Domains → PHP**.

## DirectAdmin

```bash
cd /usr/local/directadmin/custombuild
./build update && ./build php
```

## LiteSpeed / OpenLiteSpeed (lsphp)

```bash
sudo apt install --only-upgrade 'lsphp*'     # or: sudo dnf upgrade 'lsphp*'
sudo /usr/local/lsws/bin/lswsctrl restart
```

## macOS (Homebrew)

```bash
brew update && brew upgrade php
brew services restart php
```

## Windows (IIS, XAMPP, WAMP, Laragon)

1. Download the fixed build for your branch from https://windows.php.net/download/. Pick the NTS build for IIS or FastCGI, and the TS build for Apache mod_php.
2. Stop the web server, rename the old PHP folder to back it up, and extract the new build in its place.
3. Copy your `php.ini` and any extra extension DLLs over from the old folder.
4. Start the web server again and run `check.php`.

Bundles like **XAMPP** usually ship updates late. Swap the PHP folder yourself as above, or install the bundle's patched release once it's out.

## Shared hosting (no root access)

You can't patch the PHP binary yourself. Instead:

1. In the control panel (cPanel **MultiPHP Manager** / **Select PHP Version**, hPanel, Plesk), switch the site to the newest version offered: 8.3 or newer if your code supports it.
2. Upload `check.php`. On shared hosting, add your own IP to `$ALLOWED_IPS`. Open it in a browser and read the verdict, then **delete it**.
3. If it doesn't say `PATCHED`, open a support ticket with your host citing **CVE-2026-109618 and CVE-2026-109619** and ask when they will deploy PHP 8.x with the fix.

## End-of-life PHP (7.4, 8.0, 8.1)

The PHP team published **source patches only**:

- https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619
- https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619
- https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619

In order of preference:

1. Move to PHP 8.3 or newer.
2. Use a vendor that builds patched EOL binaries: your distro's LTS packages, CloudLinux alt-php, or a paid LTS provider.
3. Compile from the backport branch yourself. Advanced users only.

**PHP 5.x through 7.3 have no fix at all.** Migrate, and apply the mitigations until then.
