# php2shell-hostcheck

A free, **read-only** host check for **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619), the critical unauthenticated RCE pair in PHP fixed on 21 October 2026.

Most free PHP2Shell checkers look at your site from the outside and read the PHP version in the HTTP headers. Many servers hide that header, distro packages backport fixes without changing the version number, and the PHP that serves your site isn't always the `php` in your shell. This script runs **on the server** and checks what is actually there.

> Indicator check only. A clean result is not proof that a host is safe or uncompromised. Only run it on systems you own or are authorised to check.

## What it checks

| Check | Why it matters |
|---|---|
| **Every PHP runtime on the box**: CLI, PHP-FPM, CGI, Apache mod_php, LiteSpeed `lsphp`, cPanel EA-PHP, Plesk, Remi, CloudLinux alt-php | The web server often runs a different PHP than the command line |
| **Version vs. fixed releases** (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) | Tells you what's unpatched |
| **Distro backports** (Debian/Ubuntu changelogs, RPM changelogs) | Distros patch without bumping the upstream version, so a version check alone gives false alarms |
| **End-of-life branches** (8.1 and older) | No official fix exists, so these get flagged even with a backport |
| **Stale running workers** | If PHP was updated but PHP-FPM/Apache wasn't restarted, the old vulnerable code is still running |
| **Temporary mitigation settings** (`session.upload_progress.enabled`, `post_max_size`, `memory_limit`, `fatal_error_backtraces`) plus FPM pool / Apache overrides | Shows whether stopgaps are in place |
| **Compromise indicators** (`--ioc`, optional) | Exploitation started *before* the patch, so patching doesn't undo a break-in |

The `--ioc` indicators are: PHP files changed since a date, webshell-like code patterns, PHP inside upload folders, PHP in temp folders, crontabs for web-server users, recently changed system cron files, extra UID 0 accounts, changes to `/etc/passwd`, PHP out-of-memory errors in logs (exploit attempts trigger these), and outbound connections from PHP workers.

## What it does NOT do

- It sends **no network traffic** and **no exploit probes**.
- It **changes nothing**: no files, settings, packages or services.
- It does not scan inside Docker containers from the host (it tells you if containers are running, so you can run it inside them).
- It is not a malware scanner or a replacement for incident response.

## Quick start

Download it, **read it**, then run it. Don't pipe scripts from the internet straight into a root shell, including this one.

```bash
curl -fsSLO https://raw.githubusercontent.com/Charlie-Netdevops/php2shell-hostcheck/main/php2shell-hostcheck.sh
less php2shell-hostcheck.sh
chmod +x php2shell-hostcheck.sh
sudo ./php2shell-hostcheck.sh
```

With compromise indicators:

```bash
sudo ./php2shell-hostcheck.sh --ioc --webroot /var/www
```

Requirements: Linux, bash 4+, standard tools (`find`, `grep`, `awk`, `zgrep`). Works on Debian, Ubuntu, RHEL, Rocky, Alma, CentOS 7+, Amazon Linux and cPanel/Plesk servers. Run as root for full results.

## Options

```
--json            Machine-readable JSON output (for n8n, cron, SIEM)
--ioc             Also look for basic compromise indicators
--webroot DIR     Web root to scan with --ioc (repeatable; implies --ioc)
--since DATE      Look for changes since DATE (default 2026-10-17)
--deep            With --ioc, scan ALL PHP files for webshell patterns (slower)
--no-color        Disable colours
-V, --version     Show version
-h, --help        Show help
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Every PHP runtime found is patched, nothing else flagged |
| `1` | **Vulnerable**: unpatched or end-of-life PHP, or workers need a restart |
| `2` | **Needs attention**: unknown version, EOL with a backport, or indicators found |
| `3` | No PHP runtime found |
| `64` | Bad arguments |

## Example output

```
php2shell-hostcheck 0.1.0 — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
Host: web01 | Ubuntu 24.04.5 LTS | root: yes | data: 2026-10-22

PHP RUNTIMES
  [VULNERABLE] 8.3.6  cli  /usr/bin/php8.3  (php8.3-cli)
      update to 8.3.36 or newer, then restart PHP-FPM / the web server
      session.upload_progress.enabled=On  post_max_size=8M  memory_limit=-1
  [EOL] 7.4.33  cli  /usr/local/bin/php74
      end-of-life branch with no official fix — upgrade to 8.3+, or isolate/take offline

FINDINGS (indicators since 2026-10-17; roots: /var/www)
  [HIGH] Running PHP still uses the old binary — restart needed
      PID 812: /usr/sbin/php-fpm8.3 (deleted)
  [HIGH] Webshell-like code patterns
      /var/www/site/wp-content/themes/x/cache.php
  [MEDIUM] PHP files inside upload folders
      /var/www/site/wp-content/uploads/2026/10/img.php

RESULT: VULNERABLE — patch/upgrade PHP and restart PHP-FPM / the web server.
Indicator check only — a clean result is not proof the host is safe or uncompromised.
```

## Running it on a schedule

Cron, daily at 07:12, alerting only on problems:

```bash
12 7 * * * /opt/php2shell-hostcheck.sh --json > /var/log/php2shell-check.json; [ $? -eq 1 ] && mail -s "PHP2Shell: $(hostname) vulnerable" you@example.com < /var/log/php2shell-check.json
```

The `--json` output is built for automation tools like n8n: run it over SSH, parse the JSON, and send `result` / `findings` to Slack, Teams or Google Chat.

## If it says VULNERABLE

1. **Patch.** Install PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or your distro's fixed package. On shared or managed hosting, ask your host in writing for the installed version and the fix date.
2. **Restart** PHP-FPM / Apache / LiteSpeed, then run the check again. The stale-worker check confirms the restart took effect.
3. **End-of-life (8.1 and older):** upgrade to 8.3 or newer, or isolate the server. Source backports exist for 7.4/8.0/8.1, but you have to build them yourself.
4. **Check for compromise:** run with `--ioc`. If anything looks wrong, isolate the server, preserve the logs, and rotate credentials stored on it.

Temporary mitigations (`session.upload_progress.enabled=Off`, low `post_max_size`) reduce exposure but **are not a fix**.

## Limitations

- Version and changelog checks are only as good as the data in the script (`DATA_DATE`). Update the `FIXED` table if PHP ships a follow-up release.
- Backport detection needs the distro changelog. Minimal and container images often strip `/usr/share/doc`, so you may get "no distro changelog found".
- The webshell patterns are simple and will miss obfuscated shells and catch some legitimate code.
- Without root, other users' processes, crontabs and some configs can't be read.

## References

- PHP security advisory, 21 Oct 2026: <https://www.php.net/archive/2026.php>
- CISA alert: <https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching>
- GitHub advisories: GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp

## Contributing

Issues and pull requests are welcome, especially new PHP install locations, distro backport formats, and false-positive reports.

## Disclaimer

Provided as-is, without warranty of any kind. You are responsible for how and where you run it. See [LICENSE](LICENSE).
