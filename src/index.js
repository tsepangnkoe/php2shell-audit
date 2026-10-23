'use strict'
// php2shell-audit check engine. Passive only — never sends the PHP2Shell
// crash/DoS payload and never reads response bodies. Detection uses response
// headers (version + PHP-presence signals). Optional subdomain enumeration
// uses public Certificate Transparency logs (crt.sh) — passive public data.

const { execFile } = require('node:child_process')
const { promisify } = require('node:util')
const dns = require('node:dns').promises
const execFileP = promisify(execFile)
const { VERDICT, versionStatus, extractVersion } = require('./version')

const PKG_VERSION = require('../package.json').version
const USER_AGENT = `php2shell-audit/${PKG_VERSION} (defensive passive version check; no probes)`
const MAX_SUBDOMAINS = 1000

const LOCAL_BINARIES = [
  'php', 'php8.5', 'php8.4', 'php8.3', 'php8.2', 'php8.1', 'php8.0', 'php7.4',
  'php-fpm', 'php-fpm8.5', 'php-fpm8.4', 'php-fpm8.3', 'php-fpm8.2',
]

function makeResult(target, mode, patch) {
  return {
    target, mode,
    verdict: patch.verdict,
    php_version: patch.php_version || null,
    php_detected: patch.php_detected || false,
    signals: patch.signals || [],
    reason: patch.reason,
  }
}

// --------------------------------------------------------------------------- //
// local mode (authoritative)
// --------------------------------------------------------------------------- //
async function checkLocal() {
  const results = []
  for (const bin of LOCAL_BINARIES) {
    let banner
    try {
      const { stdout, stderr } = await execFileP(bin, ['-v'], { timeout: 15000 })
      banner = `${stdout || ''}${stderr || ''}`
    } catch (err) {
      if (err && err.code === 'ENOENT') continue
      results.push(makeResult(`localhost:${bin}`, 'local', { verdict: VERDICT.UNKNOWN, reason: `failed to run \`${bin} -v\`: ${err.message}` }))
      continue
    }
    const ver = extractVersion(banner)
    const s = ver ? versionStatus(ver) : { verdict: VERDICT.UNKNOWN, reason: `could not parse version from \`${bin} -v\`` }
    results.push(makeResult(`localhost:${bin}`, 'local', { ...s, php_version: ver, php_detected: !!ver }))
  }
  if (results.length === 0) {
    results.push(makeResult('localhost', 'local', { verdict: VERDICT.UNKNOWN, reason: 'no php / php-fpm binary found on PATH on this host' }))
  }
  return results
}

// --------------------------------------------------------------------------- //
// PHP-presence detection from headers (no body read)
// --------------------------------------------------------------------------- //
function detectSignals(headers) {
  const get = (n) => headers.get(n) || ''
  const cookies = (typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [get('set-cookie')]).filter(Boolean).join(' ; ')
  const xpb = get('x-powered-by')
  const server = get('server')
  const link = get('link')
  const signals = []
  if (/PHPSESSID/i.test(cookies)) signals.push('PHPSESSID cookie')
  if (/\bPHP\b/i.test(xpb)) signals.push('X-Powered-By: PHP')
  if (/\bPHP\b/i.test(server)) signals.push('Server mentions PHP')
  if (/wp-json|wp-content|wp-includes|wordpress/i.test(`${link} ${cookies} ${get('x-redirect-by')}`)) signals.push('WordPress (PHP)')
  if (/xmlrpc\.php/i.test(get('x-pingback'))) signals.push('X-Pingback xmlrpc.php')
  if (/\bwpdm|woocommerce|elementor/i.test(cookies)) signals.push('WordPress plugin cookie')
  // version can only legitimately come from Server / X-Powered-By
  return { versionText: `${server}\n${xpb}`, signals }
}

// --------------------------------------------------------------------------- //
// remote passive mode (headers only; follows redirects; no body read)
// --------------------------------------------------------------------------- //
async function fetchResponseHeaders(url, { timeoutMs, headers }) {
  let last
  for (const method of ['HEAD', 'GET']) {
    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(), timeoutMs)
    try {
      const res = await fetch(url, {
        method, redirect: 'follow', signal: ac.signal,
        headers: { 'User-Agent': USER_AGENT, ...headers },
      })
      if (res.body) { try { await res.body.cancel() } catch { /* ignore */ } }
      last = res
      if (![405, 501].includes(res.status)) return res
    } finally {
      clearTimeout(timer)
    }
  }
  return last
}

async function checkRemote(target, opts) {
  let url
  try {
    url = new URL(target.includes('://') ? target : `https://${target}`)
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('not an http(s) URL')
    if (url.username || url.password) throw new Error('URL credentials are not supported')
  } catch (err) {
    return makeResult(target, 'remote', { verdict: VERDICT.UNKNOWN, reason: `invalid target: ${err.message}` })
  }
  let res
  try {
    res = await fetchResponseHeaders(url, opts)
  } catch (err) {
    const hint = /certificate|self-signed|altname|SSL/i.test(err.message) ? ' (TLS error — try “Skip TLS verify”)' : ''
    return makeResult(target, 'remote', { verdict: VERDICT.UNKNOWN, reason: `request failed: ${err.message}${hint}` })
  }
  const { versionText, signals } = detectSignals(res.headers)
  const ver = extractVersion(versionText)
  if (ver) {
    const s = versionStatus(ver)
    return makeResult(target, 'remote', { ...s, php_version: ver, php_detected: true, signals, reason: `${s.reason}  [advisory only: headers can't confirm a backported fix]` })
  }
  if (signals.length) {
    return makeResult(target, 'remote', {
      verdict: VERDICT.UNKNOWN, php_detected: true, signals,
      reason: `PHP detected (${signals.join(', ')}) but the version is hidden — patch status unknown, confirm with a local \`php -v\``,
    })
  }
  return makeResult(target, 'remote', { verdict: VERDICT.UNKNOWN, signals, reason: 'no PHP version or PHP indicators in response headers (host may still run PHP)' })
}

// --------------------------------------------------------------------------- //
// passive subdomain enumeration (crt.sh CT logs + HackerTarget) + DNS resolve
// --------------------------------------------------------------------------- //
async function fetchJson(url, timeoutMs = 30000) {
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), timeoutMs)
  try {
    const res = await fetch(url, { signal: ac.signal, headers: { 'User-Agent': USER_AGENT } })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return await res.json()
  } finally { clearTimeout(timer) }
}

async function fetchText(url, timeoutMs = 30000) {
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), timeoutMs)
  try {
    const res = await fetch(url, { signal: ac.signal, headers: { 'User-Agent': USER_AGENT } })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return await res.text()
  } finally { clearTimeout(timer) }
}

async function enumerateSubdomains(domain) {
  const base = domain.toLowerCase().replace(/^\*?\.?/, '')
  const found = new Set()
  const sources = {}
  // crt.sh — certificate transparency
  try {
    const rows = await fetchJson(`https://crt.sh/?q=%25.${encodeURIComponent(base)}&output=json`)
    let n = 0
    for (const row of rows) {
      for (const name of String(row.name_value || '').split('\n')) {
        const h = name.trim().toLowerCase()
        if (h && !h.includes('*') && (h === base || h.endsWith(`.${base}`))) { found.add(h); n++ }
      }
    }
    sources['crt.sh'] = found.size
  } catch (e) { sources['crt.sh'] = `error: ${e.message}` }
  // HackerTarget — passive DNS (best-effort, rate-limited)
  try {
    const txt = await fetchText(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(base)}`)
    if (!/API count exceeded|error/i.test(txt)) {
      let n = 0
      for (const line of txt.split('\n')) {
        const h = line.split(',')[0].trim().toLowerCase()
        if (h && (h === base || h.endsWith(`.${base}`))) { found.add(h); n++ }
      }
      sources['hackertarget'] = n
    } else { sources['hackertarget'] = 'rate-limited' }
  } catch (e) { sources['hackertarget'] = `error: ${e.message}` }
  found.add(base)
  return { hosts: [...found].slice(0, MAX_SUBDOMAINS), sources }
}

async function resolves(host) {
  try { await dns.lookup(host); return true } catch { return false }
}

async function checkDomain(domain, opts, { onProgress } = {}) {
  const { hosts, sources } = await enumerateSubdomains(domain)
  if (onProgress) onProgress({ phase: 'enumerated', count: hosts.length, sources })
  // keep only hosts that resolve
  const live = []
  await pMap(hosts, 50, async (h) => { if (await resolves(h)) live.push(h) })
  if (onProgress) onProgress({ phase: 'resolved', live: live.length, total: hosts.length })
  const results = await pMap(live, opts.concurrency || 15, (h) => checkRemote(`https://${h}`, opts))
  return { enumeration: { domain, discovered: hosts.length, live: live.length, sources }, results }
}

// --------------------------------------------------------------------------- //
async function pMap(items, limit, worker) {
  const out = new Array(items.length)
  let i = 0
  const runners = Array.from({ length: Math.min(limit, items.length || 1) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await worker(items[idx], idx) }
  })
  await Promise.all(runners)
  return out
}

module.exports = { PKG_VERSION, USER_AGENT, checkLocal, checkRemote, enumerateSubdomains, checkDomain, pMap }
