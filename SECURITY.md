# Security policy

## Reporting a vulnerability in this tool

Please report security issues in `php2shell-audit` privately via GitHub's
"Report a vulnerability" (Security → Advisories) rather than a public issue.
We aim to acknowledge within 3 business days.

## Design stance

`php2shell-audit` is intentionally a **passive, version-based** checker. It does
not and will not:

- send the PHP2Shell crash / out-of-memory payload, or any exploit probe;
- send any request intended to cause a fault, exhaust memory, or disrupt a service;
- read or parse response bodies (detection uses response headers only).

It **does** support attack-surface mapping for authorized assessment:

- optional subdomain enumeration from **public Certificate Transparency logs**
  (crt.sh) and passive DNS — this reads public data and does not probe the target;
- DNS resolution of discovered names, and normal `HEAD`/`GET` header requests
  (redirects followed) to read advertised versions and PHP-presence signals.

Pull requests that add exploit probing or denial-of-service behaviour will not
be accepted — those would turn a defensive assessment tool into offensive
tooling. Enumeration and header reads are standard, non-intrusive CSIRT
attack-surface activities and must only be run against authorized scope.

## Using it responsibly

Run it only against infrastructure you own or are explicitly authorized to test.
A `VULNERABLE` verdict from a remote (header) check is advisory: confirm with a
local `--local` check or your package manager before and after remediation.
