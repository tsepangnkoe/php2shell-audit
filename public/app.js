'use strict'
// php2shell-audit web UI — talks to the local /api/check endpoint.
// No external dependencies, no inline script (CSP-friendly).

const $ = (id) => document.getElementById(id)
const CLS = { VULNERABLE: 'v', OK: 'o', UNKNOWN: 'u' }

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

function setBusy(busy) {
  $('run').disabled = busy
  $('run').textContent = busy ? 'Auditing…' : 'Run audit'
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

function renderResults(results) {
  const root = $('results')
  root.innerHTML = ''
  if (!results.length) {
    root.innerHTML = '<div class="empty">No results.</div>'
    return
  }
  // worst first
  const order = { VULNERABLE: 0, UNKNOWN: 1, OK: 2 }
  results.sort((a, b) => (order[a.verdict] ?? 3) - (order[b.verdict] ?? 3))
  for (const r of results) {
    const c = CLS[r.verdict] || 'u'
    const ver = r.php_version ? ` · <span class="ver">PHP ${esc(r.php_version)}</span>` : ''
    const el = document.createElement('div')
    el.className = `card ${c}`
    el.innerHTML =
      `<span class="badge ${c}">${esc(r.verdict)}</span>` +
      `<div class="body">` +
        `<div class="tgt">${esc(r.target)}</div>` +
        `<div class="meta">${esc(r.mode)} check${ver}</div>` +
        `<div class="why">${esc(r.reason)}</div>` +
      `</div>`
    root.appendChild(el)
  }
}

async function run() {
  showError('')
  const targets = $('targets').value
  const local = $('local').checked
  if (!targets.trim() && !local) {
    showError('Enter at least one target, or tick “check this server’s local PHP”.')
    return
  }
  setBusy(true)
  try {
    const res = await fetch('api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targets,
        local,
        insecure: $('insecure').checked,
        timeout: Number($('timeout').value) || 10,
      }),
    })
    const data = await res.json()
    if (!res.ok) throw new Error(data.error || `request failed (${res.status})`)
    renderSummary(data.counts || {})
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
