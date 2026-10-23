'use strict'
// php2shell-audit web UI — talks to the local /api/check endpoint.
// No external dependencies, no inline script (CSP-friendly).

const $ = (id) => document.getElementById(id)
const CLS = { VULNERABLE: 'v', OK: 'o', UNKNOWN: 'u' }

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

function setBusy(busy, text) {
  $('run').disabled = busy
  $('run').textContent = busy ? 'Auditing…' : 'Run audit'
  $('loadtext').textContent = text || 'checking…'
  $('loader').classList.toggle('on', busy)
}

function showError(msg) {
  $('error').innerHTML = msg ? `<div class="err">${esc(msg)}</div>` : ''
}

function renderSummary(counts) {
  $('c-v').textContent = counts.VULNERABLE || 0
  $('c-o').textContent = counts.OK || 0
  $('c-u').textContent = counts.UNKNOWN || 0
  $('summary').hidden = false
}

function renderEnumerations(enums) {
  if (!enums || !enums.length) { $('enumbar').innerHTML = ''; return }
  $('enumbar').innerHTML = enums.map((e) => {
    const src = Object.entries(e.sources || {}).map(([k, v]) => `${esc(k)}: ${esc(v)}`).join(' · ')
    return `<div class="enumbar">🔍 <b>${esc(e.domain)}</b> — discovered <b>${e.discovered}</b> names, <b>${e.live}</b> resolve in DNS and were checked. <span style="color:var(--faint)">(${src})</span></div>`
  }).join('')
}

function renderResults(results) {
  const root = $('results')
  root.innerHTML = ''
  if (!results.length) { root.innerHTML = '<div class="empty">No results.</div>'; return }
  const order = { VULNERABLE: 0, UNKNOWN: 1, OK: 2 }
  // vulnerable first; within unknown, PHP-detected before no-signal
  results.sort((a, b) =>
    (order[a.verdict] ?? 3) - (order[b.verdict] ?? 3) ||
    (b.php_detected ? 1 : 0) - (a.php_detected ? 1 : 0))
  for (const r of results) {
    const c = CLS[r.verdict] || 'u'
    const ver = r.php_version
      ? ` · <span class="ver">PHP ${esc(r.php_version)}</span>`
      : (r.php_detected ? ' · <span class="ver">PHP · version hidden</span>' : '')
    const tags = (r.signals && r.signals.length)
      ? `<div class="tags">${r.signals.map((s) => `<span class="tag">${esc(s)}</span>`).join('')}</div>` : ''
    const el = document.createElement('div')
    el.className = `card ${c}`
    el.innerHTML =
      `<span class="badge ${c}">${esc(r.verdict)}</span>` +
      `<div class="body">` +
        `<div class="tgt">${esc(r.target)}</div>` +
        `<div class="meta">${esc(r.mode)} check${ver}</div>` +
        `<div class="why">${esc(r.reason)}</div>${tags}` +
      `</div>`
    root.appendChild(el)
  }
}

async function run() {
  showError('')
  const raw = $('targets').value
  const local = $('local').checked
  const enumerate = $('enumerate').checked
  if (!raw.trim() && !local) {
    showError('Enter at least one target/domain, or tick “Check local PHP”.')
    return
  }
  setBusy(true, enumerate ? 'enumerating subdomains & checking (this can take a minute)…' : 'checking…')
  try {
    const res = await fetch('api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targets: enumerate ? '' : raw,
        domains: enumerate ? raw : '',
        local,
        enumerate,
        insecure: $('insecure').checked,
        timeout: Number($('timeout').value) || 10,
      }),
    })
    const data = await res.json()
    if (!res.ok) throw new Error(data.error || `request failed (${res.status})`)
    renderSummary(data.counts || {})
    renderEnumerations(data.enumerations)
    renderResults(data.results || [])
    if (data.version) $('ver').textContent = 'v' + data.version
  } catch (err) {
    showError(err.message)
  } finally {
    setBusy(false)
  }
}

$('run').addEventListener('click', run)
$('targets').addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run()
})
