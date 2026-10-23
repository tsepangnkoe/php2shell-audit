# Security policy

## Reporting a vulnerability in this tool

Please report security issues in `php2shell-audit` privately via GitHub's
"Report a vulnerability" (Security → Advisories) rather than a public issue.
We aim to acknowledge within 3 business days.

## Design stance

`php2shell-audit` is intentionally a **passive, version-based** checker. It does
not and will not:

- send the PHP2Shell crash / out-of-memory payload, or any exploit probe;
- enumerate, discover, or resolve third-party hosts;
- follow redirects or read response bodies.

Pull requests that add exploit probing, denial-of-service behaviour, or mass
host discovery will not be accepted — those features would turn a defensive
self-check into offensive tooling.

## Using it responsibly

Run it only against infrastructure you own or are explicitly authorized to test.
A `VULNERABLE` verdict from a remote (header) check is advisory: confirm with a
local `--local` check or your package manager before and after remediation.
