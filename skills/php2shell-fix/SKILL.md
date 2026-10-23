---
name: php2shell-fix
description: Find, patch and verify the PHP2Shell vulnerabilities (CVE-2026-109618, CVE-2026-109619) on a website or server. Use when the user mentions PHP2Shell, these CVE IDs, "the new PHP bug", "PHP RCE October 2026", or asks to check whether their PHP site, WordPress/Laravel/Drupal install, cPanel/Plesk host, Docker image or VPS is vulnerable or patched.
---

# PHP2Shell fix

PHP2Shell is two critical remote-code-execution flaws in the **PHP engine itself**, disclosed on 21 October 2026:

| CVE | Problem | Advisory |
|---|---|---|
| CVE-2026-109618 | Memory corruption during out-of-memory handling | GHSA-w8hw-w9fx-j79w |
| CVE-2026-109619 | Stale global state between requests (use-after-free) | GHSA-6wmf-4rv5-p3rp |

- **Affected:** PHP 5.4 through 8.5.11, in every SAPI that serves web requests: mod_php, PHP-FPM, php-cgi, FrankenPHP and LiteSpeed. Apache **mod_php** is the most urgent case, because the exploit runs before any application code.
- **Fixed in:** 8.5.12, 8.4.27, 8.3.36 and 8.2.35. The PHP team published only source backports for 7.4, 8.0 and 8.1, with no official binaries. Older branches get no fix.
- **Exploited in the wild** since 17 October 2026.

The bug is in PHP, not in the website's code, so **upgrading PHP is the only complete fix**. Config mitigations reduce the risk but do not make a server safe.

## Rules

- This skill is defensive only. Never write, fetch or run exploit or proof-of-concept code, and never probe a server the user does not own or administer.
- Ask the user before each change that affects a live site: package upgrades, service restarts and config edits. Back up every config file before editing it (`cp file file.bak-php2shell`).
- Copy `scripts/check.php` into a web root only for the check, and delete it right afterwards. It shows server details.
- Report results faithfully. If you can't confirm that something is patched, say so. Never assume it is.

## Workflow

### 1. Work out where PHP runs

Ask or detect which of these applies:

- **Local shell or SSH to a Linux server:** you can run commands. Use steps 2 to 7.
- **Shared hosting (cPanel, Plesk, DirectAdmin, hPanel):** you cannot upgrade the PHP binary. Go to *Shared hosting* in `references/upgrade-guide.md`.
- **Docker or Kubernetes:** the fix is rebuilding the image. See *Docker* in the upgrade guide.
- **Windows (IIS, XAMPP, WAMP, Laragon):** see *Windows* in the upgrade guide.
- **Managed platform** (managed WordPress hosting, a PaaS): the provider patches PHP. Tell the user to confirm with their provider and to check the provider's status page.

### 2. Find every PHP install

On Linux, run:

```bash
bash scripts/find-php.sh
```

It lists each PHP CLI, PHP-FPM and mod_php it finds, with a verdict for each, plus any distro changelog entries that mention the CVE IDs. A server often has several PHP versions installed. All of them need checking, but the ones serving web traffic come first.

### 3. Check the PHP that actually serves the site

`php -v` shows only the command-line PHP. To check the PHP that serves the website:

1. Copy `scripts/check.php` into the site's document root under a random name, for example `check-<8 random hex>.php`.
2. Request it from the server itself: `curl -s http://127.0.0.1/check-xxxx.php -H "Host: <site domain>"`. The script answers only localhost by default. If the user needs to open it from a browser, have them add their own IP to `$ALLOWED_IPS` in the script.
3. **Delete the file right away.**

The output includes the PHP version, SAPI, verdict and the current values of the mitigation settings.

### 4. Read the verdict

| Verdict | Meaning | Action |
|---|---|---|
| `PATCHED` | The version is at or above the fixed release for its branch | Restart workers if PHP was upgraded recently, then go to step 7 |
| `VULNERABLE` | A supported branch (8.2 to 8.5) is below its fixed release | Upgrade (step 5) |
| `EOL` | 7.4, 8.0 or 8.1 | Move to 8.3 or newer. If that's impossible right away, use a vendor's patched package. Apply mitigations meanwhile |
| `UNSUPPORTED` | Older than 7.4 | No fix exists. Migrate to a supported PHP and apply mitigations meanwhile, or take the site offline |
| `CHECK_VENDOR` | A distro build whose version number can't prove it either way | Look for the CVE IDs in the package changelog (`find-php.sh` does this). A match means patched; no match means vulnerable |

### 5. Upgrade

Follow the section of `references/upgrade-guide.md` for the platform. After upgrading:

- **Restart PHP-FPM and the web server.** Running workers keep the old, vulnerable code in memory until they restart.
- Run step 3 again and confirm the verdict is now `PATCHED`.

Moving to a new minor branch, such as 7.4 to 8.3, can break old sites. Before switching production, check the site on a staging copy, or at least confirm the user has a backup.

### 6. If upgrading is blocked: apply mitigations

Apply `mitigations/php2shell-mitigation.ini` at the server level: php.ini, the FPM pool config or the Apache vhost. Not through `ini_set()` or `.user.ini`, because those apply too late in the request. Then restart the workers, run step 3 again, and check that the "mitigation settings" section shows the recommended values. Tell the user clearly that the server is **still vulnerable**, only harder to attack, and that upgrading is still needed. If the site can't be patched or mitigated, the NSA's advice was to take it offline.

### 7. Check for signs of compromise

The bug was exploited before patches existed, so a patched server may already be compromised. Work through `references/compromise-check.md`. If you find anything suspicious, tell the user plainly. Upgrading PHP does not remove a backdoor someone already planted. Recommend restoring from a clean backup from before 17 October 2026, rotating credentials, and getting professional incident response for business sites.

### 8. Report

Finish with a short summary for each PHP install found: location, SAPI, version before, version after, verdict, mitigations applied, compromise-check result, and anything still to do. Confirm that `check.php` was deleted from every web root.
