'use strict'
const { test, before, after } = require('node:test')
const assert = require('node:assert/strict')
const http = require('node:http')
const { createServer } = require('../src/server')

let app, base, origin

before(async () => {
  // a fake PHP origin the API will check
  origin = http.createServer((req, res) => { res.setHeader('X-Powered-By', 'PHP/8.3.14'); res.end('ok') })
  await new Promise((r) => origin.listen(0, '127.0.0.1', r))
  const originUrl = `http://127.0.0.1:${origin.address().port}`

  app = createServer()
  await new Promise((r) => app.listen(0, '127.0.0.1', r))
  base = `http://127.0.0.1:${app.address().port}`
  globalThis.__origin = originUrl
})

after(() => { app.close(); origin.close() })

async function post(path, body) {
  const res = await fetch(base + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  return { status: res.status, json: await res.json() }
}

test('GET / serves the UI html', async () => {
  const res = await fetch(base + '/')
  const text = await res.text()
  assert.equal(res.status, 200)
  assert.match(text, /PHP2Shell/)
  assert.match(res.headers.get('content-security-policy') || '', /default-src 'self'/)
})

test('POST /api/check returns a verdict for a target', async () => {
  const { status, json } = await post('/api/check', { targets: globalThis.__origin })
  assert.equal(status, 200)
  assert.equal(json.results.length, 1)
  assert.equal(json.results[0].verdict, 'VULNERABLE')
  assert.equal(json.results[0].php_version, '8.3.14')
  assert.equal(json.counts.VULNERABLE, 1)
})

test('POST /api/check with no targets and no local -> 400', async () => {
  const { status, json } = await post('/api/check', {})
  assert.equal(status, 400)
  assert.ok(json.error)
})

test('path traversal is blocked', async () => {
  const res = await fetch(base + '/../package.json')
  assert.ok([403, 404].includes(res.status))
})
