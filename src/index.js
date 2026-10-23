'use strict'
// php2shell-audit check engine: local PHP binary inspection + passive HTTP
// header checks. Passive only — never sends the PHP2Shell crash/DoS payload,
// never enumerates third-party subdomains, never follows redirects or reads
// response bodies.

const { execFile } = require('node:child_process')
const { promisify } = require('node:util')
const execFileP = promisify(execFile)
const { VERDICT, versionStatus, extractVersion } = require('./version')

const PKG_VERSION = require('../package.json').version
const USER_AGENT = `php2shell-audit/${PKG_VERSION} (defensive passive version check; no probes)`

/** Candidate PHP binaries to probe in local mode. */
const LOCAL_BINARIES = [
  'php', 'php8.5', 'php8.4', 'php8.3', 'php8.2', 'php8.1', 'php8.0', 'php7.4',
  'php-fpm', 'php-fpm8.5', 'php-fpm8.4', 'php-fpm8.3', 'php-fpm8.2',
]

function makeResult(target, mode, patch) {
  return {
    target,
    mode,
    verdict: patch.verdict,
    php_version: patch.php_version || null,
    reason: patch.reason,
  }
}

// --------------------------------------------------------------------------- //
// local mode (authoritative: sees the real installed build, incl. backports)
// --------------------------------------------------------------------------- //
async function checkLocal() {
  const results = []
  for (const bin of LOCAL_BINARIES) {
    let banner
    try {
      const { stdout, stderr } = await execFileP(bin, ['-v'], { timeout: 15000 })
      banner = `${stdout || ''}${stderr || ''}`
    } catch (err) {
      // ENOENT just means this binary isn't installed; skip quietly.
      if (err && err.code === 'ENOENT') continue
      results.push(makeResult(`localhost:${bin}`, 'local', {
        verdict: VERDICT.UNKNOWN, reason: `failed to run \`${bin} -v\`: ${err.message}`,
      }))
      continue
    }
    const ver = extractVersion(banner)
    if (!ver) {
      results.push(makeResult(`localhost:${bin}`, 'local', {
        verdict: VERDICT.UNKNOWN, reason: `could not parse version from \`${bin} -v\``,
      }))
      continue
    }
    const s = versionStatus(ver)
    results.push(makeResult(`localhost:${bin}`, 'local', { ...s, php_version: ver }))
  }
  if (results.length === 0) {
    results.push(makeResult('localhost', 'local', {
      verdict: VERDICT.UNKNOWN, reason: 'no php / php-fpm binary found on PATH on this host',
    }))
  }
  return results
}

// --------------------------------------------------------------------------- //
// remote passive mode (headers only; HEAD -> GET on 405/501; no redirects/body)
// --------------------------------------------------------------------------- //
async function fetchHeaders(url, { timeoutMs, insecure, headers }) {
  const collected = []
  for (const method of ['HEAD', 'GET']) {
    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(), timeoutMs)
    let res
    try {
      res = await fetch(url, {
        method,
        redirect: 'manual',
        signal: ac.signal,
        headers: { 'User-Agent': USER_AGENT, ...headers },
        // insecure handled process-wide by caller (NODE_TLS_REJECT_UNAUTHORIZED)
      })
    } finally {
      clearTimeout(timer)
    }
    collected.push(res.headers.get('server') || '')
    collected.push(res.headers.get('x-powered-by') || '')
    // Drain/cancel the body without reading it (we never inspect bodies).
    if (res.body) { try { await res.body.cancel() } catch { /* ignore */ } }
    if (![405, 501].includes(res.status)) break
  }
  return collected.join('\n')
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
  let text
  try {
    text = await fetchHeaders(url, opts)
  } catch (err) {
    return makeResult(target, 'remote', { verdict: VERDICT.UNKNOWN, reason: `request failed: ${err.message}` })
  }
  const ver = extractVersion(text)
  if (!ver) {
    return makeResult(target, 'remote', {
      verdict: VERDICT.UNKNOWN,
      reason: 'no PHP version advertised in Server / X-Powered-By headers (host may still be vulnerable)',
    })
  }
  const s = versionStatus(ver)
  return makeResult(target, 'remote', {
    ...s,
    php_version: ver,
    reason: `${s.reason}  [advisory only: headers cannot confirm a backported fix]`,
  })
}

// --------------------------------------------------------------------------- //
// simple bounded-concurrency map
// --------------------------------------------------------------------------- //
async function pMap(items, limit, worker) {
  const out = new Array(items.length)
  let i = 0
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++
      out[idx] = await worker(items[idx], idx)
    }
  })
  await Promise.all(runners)
  return out
}

module.exports = { PKG_VERSION, USER_AGENT, checkLocal, checkRemote, pMap }
