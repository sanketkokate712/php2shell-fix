# Was this server already attacked?

Exploitation attempts were seen from **17 October 2026**, before patches existed. Patching closes the hole but doesn't remove anything an attacker already left behind. These checks are read-only.

The bug fires below the application, so the application's own logs may show little. Look at web server, PHP-FPM and system logs instead.

## 1. Signs in logs (reported by Wiz Research)

```bash
# Memory-limit fatal errors (the OOM bug path)
sudo grep -rh "Allowed memory size" /var/log/php* /var/log/apache2 /var/log/httpd /var/log/nginx 2>/dev/null | tail -50

# Bursts of HTTP 500s since 17 Oct (combined log format)
sudo awk '$9 == 500' /var/log/nginx/access.log* /var/log/apache2/access.log* /var/log/httpd/access_log* 2>/dev/null | tail -50

# Unexplained PHP-FPM worker crashes / churn
sudo grep -hE "exited on signal|SIGSEGV|SIGBUS" /var/log/php*-fpm.log /var/log/php-fpm/*.log 2>/dev/null | tail -50
```

Also watch for:

- Unusual `multipart/form-data` POSTs, often to URLs that never accept uploads, followed by memory errors.
- Unexpectedly large or malformed `PHPSESSID` cookies in responses.

## 2. New or changed files in the web root

```bash
# PHP files created or modified since 17 Oct 2026
sudo find /var/www /home/*/public_html -name '*.php' -newermt 2026-10-17 2>/dev/null

# Common web-shell patterns (expect some false positives; review each hit)
sudo grep -rlE "eval\(\s*(base64_decode|gzinflate|str_rot13)|assert\(\s*\\\$_(POST|GET|REQUEST)|system\(\s*\\\$_(POST|GET|REQUEST)" /var/www /home/*/public_html 2>/dev/null
```

## 3. Persistence

```bash
sudo crontab -l -u www-data 2>/dev/null; sudo ls -la /etc/cron.d /var/spool/cron* 2>/dev/null
sudo find /tmp /var/tmp /dev/shm -type f -newermt 2026-10-17 2>/dev/null
ps -u www-data -o pid,etime,args 2>/dev/null       # anything other than php-fpm / apache is suspicious
sudo ss -tpn state established | grep -E "php|www-data"
grep -E ":/bin/(ba)?sh$" /etc/passwd               # unexpected login users
```

## If anything looks wrong

1. Tell the user clearly and stop making changes that would destroy evidence.
2. Isolate the server: take it offline or behind maintenance mode.
3. Restore from a clean backup made **before 17 October 2026**, then patch PHP before putting it back online.
4. Rotate everything the web user could read: database passwords, API keys, `.env` secrets, admin passwords, SSH keys.
5. For business or customer-data sites, bring in professional incident response, and check data-breach reporting duties (in India, CERT-In requires reporting within 6 hours).
