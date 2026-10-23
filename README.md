# php2shell-audit

Safe, **passive** exposure checker for the **PHP2Shell** vulnerabilities
**CVE-2026-109618** and **CVE-2026-109619** — critical (CVSS 9.2) pre-auth RCE
in PHP core, patched 2026-10-21.

Built by **Ls ComCSIRT** for defenders to check **their own infrastructure**.
Zero dependencies, pure Node.js. Inspired by
[`openai/php2shell-checker`](https://github.com/openai/php2shell-checker),
extended into a multi-target CLI with local-binary inspection, concurrency, and
machine-readable reporting.

```
$ php2shell-audit --local https://intranet.example.org

php2shell-audit 1.0.0  —  CVE-2026-109618 / CVE-2026-109619  (passive, no probes)
fixed releases: 8.2.35  8.3.36  8.4.27  8.5.12   (branches <= 8.1 EOL)

[OK]         localhost:php PHP 8.3.36  (local)
      8.3.36 meets the upstream fixed release 8.3.36
[VULNERABLE] https://intranet.example.org PHP 8.2.19  (remote)
      8.2.19 is below the fixed release 8.2.35 for this branch  [advisory only: headers cannot confirm a backported fix]

============================================================
  checked: 2   vulnerable: 1   ok: 1   unknown: 0
============================================================
```

## Why this tool is safe to run against production

It is **version-based and passive**. It will **never**:

- send the PHP2Shell crash / out-of-memory payload (no "active" exploit mode exists),
- send any request meant to fault, exhaust memory, or disrupt a service,
- read or parse response bodies (detection uses response headers only).

That crash payload is the exact behaviour that made the PoC scanners in the wild
dangerous to targets — this tool omits it entirely, so you can run it against
production without risking an outage.

It **does** help you map attack surface for authorized assessment: optional
subdomain enumeration from **public Certificate Transparency logs** (crt.sh),
DNS resolution, and normal header requests (redirects followed). Enumeration
reads public data and does not probe the target. Run only against scope you own
or are authorized to assess.

## Detection signals

For each host it reads response headers and reports:

- **advertised version** from `Server` / `X-Powered-By` → `VULNERABLE` / `OK`;
- **PHP presence** even when the version is hidden — `PHPSESSID` cookie,
  WordPress (`wp-json`, plugin cookies), `X-Pingback` — reported as
  `UNKNOWN · PHP detected, version hidden → confirm locally`;
- nothing PHP-related → `UNKNOWN` (host may still run PHP behind a proxy).

## Install

Requires **Node.js ≥ 18** (uses the built-in `fetch` and `parseArgs`; no npm
dependencies).

```bash
# clone and link
git clone https://github.com/tsepangnkoe/php2shell-audit
cd php2shell-audit
npm link            # optional: puts `php2shell-audit` on your PATH

# or run directly, no install
node bin/php2shell-audit.js --help
```

## Web UI

Prefer a point-and-click check? Launch the built-in interface:

```bash
php2shell-audit serve                 # http://127.0.0.1:7627
php2shell-audit serve --port 8080     # custom port
```

Open the URL, paste one or more hosts (one per line), and get live
color-coded verdict cards plus a summary. It runs the **same passive engine**
as the CLI — no exploit probes.

> **Security:** the server binds to `127.0.0.1` by default on purpose. It fetches
> whatever URL you give it, so exposing it on a public interface (`--host 0.0.0.0`)
> turns it into an SSRF / open-proxy risk. Only bind to a wider interface on a
> trusted, access-controlled network — the tool prints a warning when you do.

## Usage (CLI)

```bash
# enumerate a domain's subdomains (CT logs) and check them all
php2shell-audit -d example.org -o report.json --all-results

# this machine (authoritative — reads the real `php -v` build)
php2shell-audit --local

# one or more web endpoints (passive header check)
php2shell-audit https://app.example.org api.example.org

# a list of your hosts, written to a JSON report
php2shell-audit --list hosts.txt -o report.json --all-results

# local box + a host list together
php2shell-audit --local --list hosts.txt
```

### Verdicts & exit codes

| Verdict | Exit | Meaning |
|---------|------|---------|
| `VULNERABLE` | `1` | below the fixed release for its branch, **or** on an EOL branch (≤ 8.1) |
| `OK` | `0` | version meets the fix (`--local` is authoritative; remote is advisory) |
| `UNKNOWN` | `3` | no version found, prerelease, hidden header, or unreachable |

The process exits `1` if **any** host is `VULNERABLE`, `0` otherwise
(`2` on a usage error). Suitable for CI / cron gating.

### Options

```
[targets...]          URLs or hostnames to check over HTTP
-l, --list FILE       file of URLs/hostnames (one per line, # comments ok)
    --local           inspect PHP binaries on this machine
-c, --concurrency N   network concurrency (default 10)
    --timeout N       per-request timeout in seconds (default 10)
-k, --insecure        disable TLS certificate verification
-H, --header K:V      extra request header (repeatable)
    --json            print JSON to stdout
-o, --output FILE     write a JSON report to FILE
    --all-results     include non-vulnerable hosts in the report
    --no-color        disable colored output  (also honors NO_COLOR)
-h, --help            -v, --version
```

## What "OK" and "UNKNOWN" really mean

- **Remote checks are advisory only.** HTTP headers show the *advertised*
  version. They cannot see a distro **backported** fix (a host may be patched
  but still advertise an old number) and a host that hides `X-Powered-By` /
  `Server` returns **UNKNOWN** — it may still be vulnerable. For a definitive
  answer, run `--local` on the host.
- **`OK` describes the version, not the installed binary.** Only `--local`
  inspects the actual build.

See [`SECURITY.md`](SECURITY.md) and the vulnerability brief for the full story.

## Fixed releases

| Branch | Fixed in |
|--------|----------|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| ≤ 8.1 | end-of-life — no numbered fix, always treated as exposed |

Both CVEs are fixed by the same releases (PHP advisory, 2026-10-21).

## Remediation

1. Upgrade PHP to the fixed release for your branch, or off an EOL branch.
2. If you can't patch immediately, consider taking the PHP service offline
   (per CISA / NCSC guidance). No `php.ini` change fully mitigates the issue.
3. Watch for post-exploitation: PHP processes spawning shells or downloading
   files, and memory-limit fatals in web-server error logs.

## Development

```bash
node --test          # run the unit + integration test suite
```

## Scope & authorization

You are responsible for running this only against infrastructure you own or are
authorized to test or assess. Subdomain enumeration reads only public
Certificate Transparency data; the checks themselves are passive header reads.

## License

[Apache-2.0](LICENSE) — Copyright © 2026 Ls ComCSIRT. Based on prior art from
`openai/php2shell-checker` (also Apache-2.0).
