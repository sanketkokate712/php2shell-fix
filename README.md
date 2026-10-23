# php2shell-fix

A Claude Code skill and scripts that find, patch and verify **PHP2Shell** (CVE-2026-109618 and CVE-2026-109619) on any PHP website or server.

> PHP2Shell is two critical remote-code-execution flaws in the PHP engine, affecting **PHP 5.4 through 8.5.11** on every web setup (mod_php, PHP-FPM, CGI, LiteSpeed, FrankenPHP). It is being exploited in the wild. The fix is to upgrade to **8.5.12, 8.4.27, 8.3.36 or 8.2.35**.
>
> Discovered by Ryan Austin (Calif) and, independently, by Wiz Research. This repo is an independent remediation tool and isn't affiliated with the PHP project, Calif or Wiz.

## What it does

1. Finds **every** PHP on the server: CLI, PHP-FPM, Apache mod_php, cPanel/Plesk/CloudLinux builds and Docker containers.
2. Checks the PHP that **actually serves your site**. `php -v` often shows a different PHP from the one the website runs.
3. Handles distro backports. It looks for the CVE IDs in the Ubuntu, Debian or RHEL package changelogs.
4. Walks you through the right upgrade for your platform, then verifies the result.
5. Applies the official temporary mitigations if you can't upgrade yet.
6. Checks for signs that the server was already attacked.

It never runs exploit code, and it asks before changing anything.

## Install the Claude skill

**Option A: as a plugin (recommended)**

```
/plugin marketplace add sanketkokate712/php2shell-fix
/plugin install php2shell-fix@php2shell-fix
```

**Option B: copy the skill folder**

```bash
git clone https://github.com/sanketkokate712/php2shell-fix.git
cp -r php2shell-fix/skills/php2shell-fix ~/.claude/skills/
```

Then, in Claude Code on your server or project, ask:

> Check this server for PHP2Shell and fix it.

## Use without Claude

```bash
# Linux server: find all PHP installs and their status
bash skills/php2shell-fix/scripts/find-php.sh

# Check the PHP that serves your website
cp skills/php2shell-fix/scripts/check.php /var/www/html/check-$(openssl rand -hex 4).php
curl -s http://127.0.0.1/check-XXXX.php       # use the name from the line above
rm /var/www/html/check-XXXX.php              # always delete it afterwards
```

Then follow [the upgrade guide](skills/php2shell-fix/references/upgrade-guide.md) for your platform, and run [the compromise checks](skills/php2shell-fix/references/compromise-check.md).

| Verdict | Meaning |
|---|---|
| `PATCHED` | Safe from PHP2Shell |
| `VULNERABLE` | Upgrade now |
| `EOL` | 7.4/8.0/8.1: move to 8.3 or newer, or use a vendor-patched build |
| `UNSUPPORTED` | Older than 7.4: no fix exists, migrate |
| `CHECK_VENDOR` | Distro build: look for the CVE IDs in the package changelog |

## Official sources

- PHP announcement: https://www.php.net/archive/2026.php#2026-10-21-5
- CVE-2026-109618: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- CVE-2026-109619: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- CISA alert: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching

## License

MIT. See [LICENSE](LICENSE). Use at your own risk: back up before upgrading, and test on staging where you can.
