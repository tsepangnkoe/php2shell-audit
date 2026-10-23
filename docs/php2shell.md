# PHP2Shell — CVE-2026-109618 / CVE-2026-109619 brief

*Compiled 2026-10-23. Verify version numbers against php.net before acting on them.*

## Summary
Two critical vulnerabilities in **PHP core** (not a specific CMS, framework, or
plugin), both rated **CVSS v4.0 9.2**, enabling **unauthenticated remote code
execution**. Discovered by researchers at Calif, OpenAI, and Wiz. Patches
released **2026-10-21**; disclosure was pulled forward one day after the CVE
IDs, a PoC, and Chainguard's fixed images leaked ahead of the embargo.

| CVE | Nature (per vendor advisories) |
|-----|--------------------------------|
| CVE-2026-109618 | RCE via out-of-memory corruption |
| CVE-2026-109619 | RCE via stale global state |

> **Note on root cause.** Some third-party scanner write-ups describe this as a
> "multipart body parser" bug triggered by "array keys nested 62 levels deep,"
> and split the two CVEs cleanly as "mod_php vs PHP-FPM." The vendor advisories
> I reviewed describe the two flaws as *out-of-memory corruption* and *stale
> global state* in memory management and error handling — code paths nearly
> every request touches. Treat the specific "62-level multipart" mechanism as
> **unconfirmed** unless you see it in the official php.net advisory.

## Why it's dangerous
- **Pre-auth.** No login, session, or vulnerable endpoint needed — any reachable
  PHP endpoint (login page, static form, health check) is exposed.
- **Runtime-level.** Independent of the application code, CMS, framework, or
  plugins. WordPress, Magento, Laravel, etc. are all affected if the PHP
  runtime underneath is unpatched.
- **Near-invisible.** Reported behavior: responses can return HTTP 200, worker
  processes stay up, and application logs record nothing because no application
  code runs. The only server-side trace may be a single memory-limit fatal in
  the web server error log — easily dismissed as noise.
- **Under active exploitation.** Honeypot hits (AWS MadPot, ELLIO, VulnCheck)
  and multiple PoCs appeared within hours of disclosure. A malicious scanner
  user-agent `php2shell-scan/109618` has been observed in the wild.

## Affected versions
Every release **below the fixed version on each branch** is affected. The bug
reaches back across the 7.x and 8.x series; some reports trace it as far as PHP
5.4. End-of-life branches (7.4, 8.0, 8.1 and older) get **no numbered fix** —
PHP published source backports only, and distro/LTS vendors shipped their own
packages, so check the vendor package version, not just the branch.

## Fixed releases (php.net advisory, 2026-10-21)
| Branch | Fixed in | Below this = exposed |
|--------|----------|----------------------|
| 8.5 | **8.5.12** | < 8.5.12 |
| 8.4 | **8.4.27** | < 8.4.27 |
| 8.3 | **8.3.36** | < 8.3.36 |
| 8.2 | **8.2.35** | < 8.2.35 |
| 8.1 and older | EOL — backport only | always treat as exposed |

The same fixed releases address **both** CVEs.

## Mitigation / remediation
1. **Patch now** to the fixed release for your branch, or upgrade off an EOL
   branch. This is the only real fix.
2. If you can't patch immediately, consider taking the PHP service offline
   (guidance echoed by CISA and NCSC).
3. **No config change fully mitigates this.** Disabling `session.upload_progress`
   only blocks one confirmed path of CVE-2026-109619, not the whole issue.
4. Watch for post-exploitation, not the exploit itself: PHP processes spawning
   shells or downloading files; unexpected outbound connections; memory-limit
   fatals in web-server error logs.
5. **Confirm the running build**, not just the advertised banner. A distro may
   ship a backported fix under an old-looking version number, and a server may
   hide its version header entirely. `php -v` on the box is authoritative.

## How this tool checks exposure
- `--local` / `--ssh-hosts`: read the real `php -v` banner (authoritative).
- `--targets` / `--url`: read advertised version from `Server` / `X-Powered-By`
  headers (advisory only — cannot see a backported fix or a hidden header).
- It is **version-based and passive**. It never sends the crash/DoS payload and
  never enumerates third-party subdomains.

## Sources
- Help Net Security — https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/
- SOCRadar — https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/
- watchTowr FAQ — https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
- TuxCare patch guide — https://tuxcare.com/blog/php2shell-cve/
- Brandefense — https://brandefense.io/blog/php2shell-php-rce-cve-2026-109618-109619/
- The Hacker News (threat-intel/exploitation timeline) — reporting by Ravie Lakshmanan, 2026-10-22
- Primary source to verify against: https://www.php.net/ (security advisories)
