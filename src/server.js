'use strict'
// Local web UI for php2shell-audit. Serves a single-page app and a JSON API
// that runs the SAME passive checks as the CLI. No probes, no body reads.
// Binds to 127.0.0.1 by default — exposing an arbitrary-URL fetcher on a
// public interface is an SSRF / open-proxy risk.

const http = require('node:http')
const fs = require('node:fs')
const path = require('node:path')
const { checkRemote, checkLocal, checkDomain, pMap, PKG_VERSION } = require('./index')
const { FIXED_IN } = require('./version')

const PUBLIC_DIR = path.join(__dirname, '..', 'public')
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' }
const MAX_TARGETS = 200

function send(res, code, body, type = 'application/json') {
  res.writeHead(code, {
    'Content-Type': type,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
  })
  res.end(body)
}

function readBody(req, limit = 128 * 1024) {
  return new Promise((resolve, reject) => {
    let data = ''; let size = 0
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('request body too large')); req.destroy() } else data += c })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })
}

const splitList = (raw) => String(raw || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)

async function handleApi(req, res, body) {
  let p
  try { p = JSON.parse(body || '{}') } catch { return send(res, 400, JSON.stringify({ error: 'invalid JSON' })) }

  const includeLocal = p.local === true
  const enumerate = p.enumerate === true
  let targets = splitList(p.targets).slice(0, MAX_TARGETS)
  let domains = splitList(p.domains)
  if (enumerate && targets.length) { domains = domains.concat(targets); targets = [] }

  if (!includeLocal && targets.length === 0 && domains.length === 0) {
    return send(res, 400, JSON.stringify({ error: 'provide targets, domains, or set local:true' }))
  }

  const opts = {
    timeoutMs: Math.min(Math.max(Number(p.timeout) || 10, 1), 60) * 1000,
    concurrency: 15,
    headers: {},
  }

  const prevTls = process.env.NODE_TLS_REJECT_UNAUTHORIZED
  if (p.insecure === true) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
  const results = []
  const enumerations = []
  try {
    if (includeLocal) results.push(...await checkLocal())
    for (const d of domains.slice(0, 20)) {
      const { enumeration, results: r } = await checkDomain(d, opts)
      enumerations.push(enumeration)
      results.push(...r)
    }
    if (targets.length) results.push(...await pMap(targets, 15, (t) => checkRemote(t, opts)))
  } finally {
    if (p.insecure === true) {
      if (prevTls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED
      else process.env.NODE_TLS_REJECT_UNAUTHORIZED = prevTls
    }
  }

  const counts = { VULNERABLE: 0, OK: 0, UNKNOWN: 0 }
  for (const r of results) counts[r.verdict] = (counts[r.verdict] || 0) + 1

  send(res, 200, JSON.stringify({
    tool: 'php2shell-audit', version: PKG_VERSION,
    scanned_at: new Date().toISOString(), fixed_versions: FIXED_IN,
    enumerations, counts, results,
  }))
}

function serveStatic(req, res) {
  let rel = decodeURIComponent(new URL(req.url, 'http://localhost').pathname)
  if (rel === '/') rel = '/index.html'
  const full = path.join(PUBLIC_DIR, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''))
  if (!full.startsWith(PUBLIC_DIR)) return send(res, 403, 'forbidden', 'text/plain')
  fs.readFile(full, (err, buf) => {
    if (err) return send(res, 404, 'not found', 'text/plain')
    send(res, 200, buf, MIME[path.extname(full)] || 'application/octet-stream')
  })
}

function createServer() {
  return http.createServer(async (req, res) => {
    try {
      if (req.method === 'POST' && req.url === '/api/check') return await handleApi(req, res, await readBody(req))
      if (req.method === 'GET') return serveStatic(req, res)
      send(res, 405, JSON.stringify({ error: 'method not allowed' }))
    } catch (err) { send(res, 500, JSON.stringify({ error: err.message })) }
  })
}

function serve({ host = '127.0.0.1', port = 7627 } = {}) {
  const server = createServer()
  return new Promise((resolve) => {
    server.listen(port, host, () => {
      const addr = server.address()
      if (host !== '127.0.0.1' && host !== 'localhost') {
        process.stderr.write('\n  ⚠  WARNING: bound to a non-local interface. This exposes an\n'
          + '     arbitrary-URL fetcher to the network (SSRF / open-proxy risk).\n'
          + '     Only do this on a trusted, access-controlled network.\n')
      }
      process.stdout.write(`\n  php2shell-audit web UI  →  http://${host === '0.0.0.0' ? 'localhost' : host}:${addr.port}\n`)
      process.stdout.write('  passive checks only · Ctrl+C to stop\n\n')
      resolve(server)
    })
  })
}

module.exports = { serve, createServer }
