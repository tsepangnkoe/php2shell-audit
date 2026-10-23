'use strict'
const { test } = require('node:test')
const assert = require('node:assert/strict')
const { versionStatus, extractVersion, VERDICT } = require('../src/version')

const v = (s) => versionStatus(s).verdict

test('versions below the branch fix are VULNERABLE', () => {
  for (const s of ['8.2.34', '8.3.14', '8.3.35', '8.4.26', '8.5.11', '8.4.0']) {
    assert.equal(v(s), VERDICT.VULNERABLE, s)
  }
})

test('versions at or above the branch fix are OK', () => {
  for (const s of ['8.2.35', '8.3.36', '8.4.27', '8.5.12', '8.5.20', '8.3.100']) {
    assert.equal(v(s), VERDICT.OK, s)
  }
})

test('EOL branches are always VULNERABLE, even with a high patch number', () => {
  for (const s of ['7.4.33', '8.1.35', '8.0.30', '5.6.40', '7.2.34']) {
    assert.equal(v(s), VERDICT.VULNERABLE, s)
  }
})

test('future / unlisted branches are UNKNOWN', () => {
  for (const s of ['8.6.0', '9.0.1']) assert.equal(v(s), VERDICT.UNKNOWN, s)
})

test('prereleases are UNKNOWN', () => {
  for (const s of ['8.4.0-dev', '8.3.36RC1', '8.5.12-beta3', '8.2.35-alpha1']) {
    assert.equal(v(s), VERDICT.UNKNOWN, s)
  }
})

test('garbage is UNKNOWN', () => {
  for (const s of ['', 'nope', '8.3', '8', 'x.y.z', null, undefined]) {
    assert.equal(v(s), VERDICT.UNKNOWN, JSON.stringify(s))
  }
})

test('extractVersion parses common banner / header forms', () => {
  assert.equal(extractVersion('PHP/8.3.14'), '8.3.14')
  assert.equal(extractVersion('Server: Apache; X: PHP 8.4.27'), '8.4.27')
  assert.equal(extractVersion('php/8.2.35'), '8.2.35')
  assert.equal(extractVersion('PHP 8.4.26 (cli) (built: Oct 1 2026)'), '8.4.26')
})

test('extractVersion prefers the worst verdict when several appear', () => {
  assert.equal(extractVersion('PHP/8.5.12\nPHP/8.3.14'), '8.3.14')
})

test('extractVersion returns null when absent', () => {
  assert.equal(extractVersion('Server: nginx'), null)
  assert.equal(extractVersion(''), null)
})
