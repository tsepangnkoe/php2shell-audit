#!/usr/bin/env node
'use strict'
// php2shell-audit CLI — safe, passive PHP2Shell (CVE-2026-109618 / 109619)
// exposure checker for infrastructure you own.

const fs = require('node:fs')
const { parseArgs } = require('node:util')
const { VERDICT, EXIT_CODE, FIXED_IN } = require('../src/version')
const { PKG_VERSION, checkLocal, checkRemote, pMap } = require('../src/index')

const USAGE = `php2shell-audit ${PKG_VERSION} — passive PHP2Shell (CVE-2026-109618 / CVE-2026-109619) checker

USAGE
  php2shell-audit [targets...] [options]
  php2shell-audit --local
  php2shell-audit https://app.example.com api.example.com
  php2shell-audit -l hosts.txt -o report.json

INPUT (at least one)
  [targets...]        URLs or hostnames to check passively over HTTP
  -l, --list FILE     file of URLs/hostnames, one per line (# comments ok)
  --local             inspect PHP binaries on THIS machine (authoritative)

OPTIONS
  -c, --concurrency N network concurrency (default 10)
      --timeout N     per-request timeout in seconds (default 10)
  -k, --insecure      disable TLS certificate verification
  -H, --header K:V    extra request header (repeatable)
      --json          print machine-readable JSON to stdout
  -o, --output FILE   write JSON report to FILE
      --all-results   include non-vulnerable hosts in the JSON report
      --no-color      disable colored output
  -h, --help          show this help
  -v, --version       show version

This tool is version-based and passive. It never sends the PHP2Shell crash/DoS
payload, never enumerates third-party subdomains, and never follows redirects
or reads response bodies. Scope it to hosts you are authorized to test.

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

async function main(argv) {
  let parsed
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        local: { type: 'boolean', default: false },
        list: { type: 'string', short: 'l' },
        concurrency: { type: 'string', short: 'c', default: '10' },
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
  if (!o.local && targets.length === 0) {
    process.stderr.write(`Nothing to check. Provide targets, --list FILE, or --local.\n\n${USAGE}\n`)
    return EXIT_CODE.USAGE
  }

  const concurrency = Math.max(1, Number(o.concurrency) || 10)
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

  if (o.local) results.push(...await checkLocal())
  if (targets.length) {
    const opts = { timeoutMs: timeout * 1000, insecure: o.insecure, headers }
    results.push(...await pMap(targets, concurrency, (t) => checkRemote(t, opts)))
  }

  const counts = { VULNERABLE: 0, OK: 0, UNKNOWN: 0 }
  for (const r of results) counts[r.verdict] = (counts[r.verdict] || 0) + 1

  if (o.json) {
    process.stdout.write(`${JSON.stringify(buildReport(results, o), null, 2)}\n`)
  } else {
    process.stdout.write(`php2shell-audit ${PKG_VERSION}  —  CVE-2026-109618 / CVE-2026-109619  (passive, no probes)\n`)
    process.stdout.write(`fixed releases: ${Object.entries(FIXED_IN).map(([b, p]) => `${b}.${p}`).join('  ')}   (branches <= 8.1 EOL)\n\n`)
    for (const r of results) {
      const ver = r.php_version ? ` PHP ${r.php_version}` : ''
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
