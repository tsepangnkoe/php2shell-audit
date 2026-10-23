'use strict'
const { test, before, after } = require('node:test')
const assert = require('node:assert/strict')
const http = require('node:http')
const { checkRemote } = require('../src/index')
const { VERDICT } = require('../src/version')

let server
let base

before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/vuln') res.setHeader('X-Powered-By', 'PHP/8.3.14')
    else if (req.url === '/ok') res.setHeader('X-Powered-By', 'PHP/8.3.36')
    else if (req.url === '/eol') res.setHeader('X-Powered-By', 'PHP/8.1.35')
    else if (req.url === '/head405' && req.method === 'HEAD') { res.statusCode = 405; res.end(); return }
    else if (req.url === '/head405') { res.setHeader('X-Powered-By', 'PHP/8.4.26') }
    // /silent advertises nothing
    res.end('ok')
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  base = `http://127.0.0.1:${server.address().port}`
})

after(() => server.close())

const opts = { timeoutMs: 5000, insecure: false, headers: {} }

test('advertised vulnerable version -> VULNERABLE', async () => {
  const r = await checkRemote(`${base}/vuln`, opts)
  assert.equal(r.verdict, VERDICT.VULNERABLE)
  assert.equal(r.php_version, '8.3.14')
})

test('advertised fixed version -> OK', async () => {
  const r = await checkRemote(`${base}/ok`, opts)
  assert.equal(r.verdict, VERDICT.OK)
})

test('advertised EOL branch -> VULNERABLE', async () => {
  const r = await checkRemote(`${base}/eol`, opts)
  assert.equal(r.verdict, VERDICT.VULNERABLE)
})

test('HEAD 405 falls back to GET', async () => {
  const r = await checkRemote(`${base}/head405`, opts)
  assert.equal(r.php_version, '8.4.26')
  assert.equal(r.verdict, VERDICT.VULNERABLE)
})

test('no advertised version -> UNKNOWN', async () => {
  const r = await checkRemote(`${base}/silent`, opts)
  assert.equal(r.verdict, VERDICT.UNKNOWN)
})

test('invalid target -> UNKNOWN', async () => {
  const r = await checkRemote('ftp://example.com', opts)
  assert.equal(r.verdict, VERDICT.UNKNOWN)
})
