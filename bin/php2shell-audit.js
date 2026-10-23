#!/usr/bin/env node
'use strict'
// php2shell-audit CLI — safe, passive PHP2Shell (CVE-2026-109618 / 109619)
// exposure checker for infrastructure you own.

const fs = require('node:fs')
const { parseArgs } = require('node:util')
const { VERDICT, EXIT_CODE, FIXED_IN } = require('../src/version')
const { PKG_VERSION, checkLocal, checkRemote, checkDomain, pMap } = require('../src/index')

const USAGE = `php2shell-audit ${PKG_VERSION} — passive PHP2Shell (CVE-2026-109618 / CVE-2026-109619) checker

USAGE
  php2shell-audit [targets...] [options]
  php2shell-audit --local
  php2shell-audit -d gov.ls                 # enumerate subdomains + check
  php2shell-audit https://app.example.com api.example.com
  php2shell-audit -l hosts.txt -o report.json
  php2shell-audit serve [--port 7627] [--host 127.0.0.1]   # launch the web UI

INPUT (at least one)
  [targets...]        URLs or hostnames to check passively over HTTP
  -d, --domain DOMAIN enumerate subdomains (crt.sh CT logs) then check; repeatable
  -l, --list FILE     file of URLs/hostnames, one per line (# comments ok)
  --local             inspect PHP binaries on THIS machine (authoritative)

OPTIONS
  -c, --concurrency N network concurrency (default 15)
      --timeout N     per-request timeout in seconds (default 10)
  -k, --insecure      disable TLS certificate verification
  -H, --header K:V    extra request header (repeatable)
      --json          print machine-readable JSON to stdout
  -o, --output FILE   write JSON report to FILE
      --all-results   include non-vulnerable hosts in the JSON report
      --no-color      disable colored output
  -h, --help          show this help
  -v, --version       show version

Passive only: never sends the PHP2Shell crash/DoS payload and never reads
response bodies. Subdomain enumeration uses public Certificate Transparency
logs. Scope it to infrastructure you are authorized to assess.

Fixed releases: 8.2.35  8.3.36  8.4.27  8.5.12   (branches <= 8.1 are EOL — always exposed)`

function readLines(path) {
  return fs.readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
}

const COLORS = { VULNERABLE: '\x1b[31m', OK: '\x1b[32m', UNKNOWN: '\x1b[33m' }
function colorize(verdict, s, enabled) {
  if (!enabled) return s
  return `${COLORS[verdict] || ''}${s}\x1b[0m`
}

async function serveCmd(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      port: { type: 'string', default: '7627' },
      host: { type: 'string', default: '127.0.0.1' },
    },
  })
  const { serve } = require('../src/server')
  await serve({ host: values.host, port: Number(values.port) || 7627 })
  return new Promise(() => {}) // run until Ctrl+C
}

async function main(argv) {
  if (argv[0] === 'serve') return serveCmd(argv.slice(1))
  let parsed
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        local: { type: 'boolean', default: false },
        domain: { type: 'string', short: 'd', multiple: true, default: [] },
        list: { type: 'string', short: 'l' },
        concurrency: { type: 'string', short: 'c', default: '15' },
        timeout: { type: 'string', default: '10' },
        insecure: { type: 'boolean', short: 'k', default: false },
        header: { type: 'string', short: 'H', multiple: true, default: [] },
        json: { type: 'boolean', default: false },
        output: { type: 'string', short: 'o' },
        'all-results': { type: 'boolean', default: false },
        'no-color': { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'v', default: false },
      },
    })
  } catch (err) {
    process.stderr.write(`${err.message}\n\n${USAGE}\n`)
    return EXIT_CODE.USAGE
  }

  const o = parsed.values
  if (o.help) { process.stdout.write(`${USAGE}\n`); return EXIT_CODE.OK }
  if (o.version) { process.stdout.write(`${PKG_VERSION}\n`); return EXIT_CODE.OK }

  const targets = [...parsed.positionals]
  if (o.list) {
    try { targets.push(...readLines(o.list)) }
    catch (err) { process.stderr.write(`cannot read --list: ${err.message}\n`); return EXIT_CODE.USAGE }
  }
  const domains = o.domain || []
  if (!o.local && targets.length === 0 && domains.length === 0) {
    process.stderr.write(`Nothing to check. Provide targets, -d DOMAIN, --list FILE, or --local.\n\n${USAGE}\n`)
    return EXIT_CODE.USAGE
  }

  const concurrency = Math.max(1, Number(o.concurrency) || 15)
  const timeout = Number(o.timeout)
  if (!(timeout > 0 && timeout <= 120)) {
    process.stderr.write('--timeout must be > 0 and <= 120 seconds\n'); return EXIT_CODE.USAGE
  }
  const headers = {}
  for (const h of o.header) {
    const i = h.indexOf(':')
    if (i > 0) headers[h.slice(0, i).trim()] = h.slice(i + 1).trim()
  }
  if (o.insecure) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

  const color = process.stdout.isTTY && !o['no-color'] && !process.env.NO_COLOR
  const results = []
  const opts = { timeoutMs: timeout * 1000, concurrency, headers }
  const quiet = o.json

  if (o.local) results.push(...await checkLocal())
  for (const d of domains) {
    if (!quiet) process.stderr.write(`[*] enumerating subdomains of ${d} (crt.sh) …\n`)
    const { enumeration, results: r } = await checkDomain(d, opts, {
      onProgress: (ev) => {
        if (quiet) return
        if (ev.phase === 'enumerated') process.stderr.write(`    discovered ${ev.count} unique names\n`)
        if (ev.phase === 'resolved') process.stderr.write(`    ${ev.live} resolve in DNS — checking …\n`)
      },
    })
    void enumeration
    results.push(...r)
  }
  if (targets.length) results.push(...await pMap(targets, concurrency, (t) => checkRemote(t, opts)))

  const counts = { VULNERABLE: 0, OK: 0, UNKNOWN: 0 }
  for (const r of results) counts[r.verdict] = (counts[r.verdict] || 0) + 1

  if (o.json) {
    process.stdout.write(`${JSON.stringify(buildReport(results, o), null, 2)}\n`)
  } else {
    process.stdout.write(`php2shell-audit ${PKG_VERSION}  —  CVE-2026-109618 / CVE-2026-109619  (passive, no probes)\n`)
    process.stdout.write(`fixed releases: ${Object.entries(FIXED_IN).map(([b, p]) => `${b}.${p}`).join('  ')}   (branches <= 8.1 EOL)\n\n`)
    for (const r of results) {
      const ver = r.php_version ? ` PHP ${r.php_version}` : (r.php_detected ? ' PHP (version hidden)' : '')
      process.stdout.write(`${colorize(r.verdict, `[${r.verdict}]`, color)} ${r.target}${ver}  (${r.mode})\n      ${r.reason}\n`)
    }
    process.stdout.write(`\n${'='.repeat(60)}\n`)
    process.stdout.write(`  checked: ${results.length}   `
      + `${colorize('VULNERABLE', `vulnerable: ${counts.VULNERABLE}`, color)}   `
      + `${colorize('OK', `ok: ${counts.OK}`, color)}   `
      + `${colorize('UNKNOWN', `unknown: ${counts.UNKNOWN}`, color)}\n`)
    process.stdout.write(`${'='.repeat(60)}\n`)
  }

  if (o.output) {
    fs.writeFileSync(o.output, `${JSON.stringify(buildReport(results, o), null, 2)}\n`)
    if (!o.json) process.stdout.write(`report written to ${o.output}\n`)
  }

  return counts.VULNERABLE > 0 ? EXIT_CODE.VULNERABLE : EXIT_CODE.OK
}

function buildReport(results, o) {
  const keep = o['all-results'] ? results : results.filter((r) => r.verdict === VERDICT.VULNERABLE)
  return {
    tool: 'php2shell-audit',
    version: PKG_VERSION,
    scanned_at: new Date().toISOString(),
    fixed_versions: FIXED_IN,
    total_results: keep.length,
    results: keep,
  }
}

main(process.argv.slice(2))
  .then((code) => { process.exitCode = code })
  .catch((err) => { process.stderr.write(`fatal: ${err.stack || err}\n`); process.exitCode = 1 })
