# Changelog

## 0.1.0 — 2026-10-22

First release.

- Finds PHP runtimes: CLI, PHP-FPM, CGI, Apache mod_php, LiteSpeed, cPanel EA-PHP, Plesk, Remi, CloudLinux alt-php
- Compares versions against the 21 Oct 2026 fixed releases (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)
- Detects Debian/Ubuntu and RPM distro backports from package changelogs
- Flags end-of-life branches (8.1 and older)
- Detects running workers still using a replaced PHP binary (restart needed)
- Reports temporary mitigation settings and FPM pool / Apache overrides
- Optional `--ioc` compromise indicators
- Text and `--json` output, documented exit codes
