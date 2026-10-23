'use strict'
// Pure, dependency-free PHP version logic for PHP2Shell
// (CVE-2026-109618 / CVE-2026-109619). No I/O here so it is trivially testable.

// Official PHP releases fixing both CVEs, published 2026-10-21.
const FIXED_IN = { '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 }

// End-of-life branches: upstream ships no numbered fix, so a high patch number
// here does NOT mean patched. Always treat as exposed unless a vendor backport
// is confirmed out-of-band.
const EOL_BRANCHES = new Set([
  '5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1',
])

const VERDICT = Object.freeze({ VULNERABLE: 'VULNERABLE', OK: 'OK', UNKNOWN: 'UNKNOWN' })
const EXIT_CODE = Object.freeze({ OK: 0, VULNERABLE: 1, UNKNOWN: 3, USAGE: 2 })

const VERSION_RE = /^(\d+)\.(\d+)\.(\d+)([-+~].*)?$/
const PRERELEASE_RE = /(?:^|[-+~.])(?:dev|alpha|beta|rc|snapshot)/i
// Matches "PHP/8.3.14", "PHP 8.3.14", "PHP 8.4.26 (cli)" in headers or `php -v`.
const BANNER_RE = /\bPHP[ /]v?(\d+\.\d+\.\d+[^\s,;)]*)/gi

/**
 * Classify a bare PHP version string.
 * @returns {{verdict: string, reason: string, branch: string|null}}
 */
function versionStatus(version) {
  const m = VERSION_RE.exec((version || '').trim())
  if (!m) return { verdict: VERDICT.UNKNOWN, reason: `unrecognized version string: ${JSON.stringify(version)}`, branch: null }
  if (PRERELEASE_RE.test(m[4] || '')) {
    return { verdict: VERDICT.UNKNOWN, reason: `prerelease build (${version}) is not covered by the fixed-version table`, branch: null }
  }
  const [major, minor, patch] = [Number(m[1]), Number(m[2]), Number(m[3])]
  const branch = `${major}.${minor}`
  if (EOL_BRANCHES.has(branch)) {
    return {
      verdict: VERDICT.VULNERABLE,
      reason: `branch ${branch} is end-of-life and receives no upstream fix for PHP2Shell (a high patch number such as ${version} does NOT mean patched)`,
      branch,
    }
  }
  const fixed = FIXED_IN[branch]
  if (fixed === undefined) {
    return { verdict: VERDICT.UNKNOWN, reason: `branch ${branch} is not in the advisory's fixed-version table; verify against php.net`, branch }
  }
  if (patch < fixed) {
    return { verdict: VERDICT.VULNERABLE, reason: `${version} is below the fixed release ${branch}.${fixed} for this branch`, branch }
  }
  return { verdict: VERDICT.OK, reason: `${version} meets the upstream fixed release ${branch}.${fixed}`, branch }
}

/**
 * Pull a PHP version out of banner/header text. When several appear, prefer the
 * one with the worst verdict so a reassuring banner can't mask a vulnerable one.
 * @returns {string|null}
 */
function extractVersion(text) {
  if (!text) return null
  let chosen = null
  let chosenVerdict = null
  for (const m of text.matchAll(BANNER_RE)) {
    const cand = m[1]
    const { verdict } = versionStatus(cand)
    if (chosen === null || verdict === VERDICT.VULNERABLE || chosenVerdict === VERDICT.OK) {
      chosen = cand
      chosenVerdict = verdict
    }
    if (chosenVerdict === VERDICT.VULNERABLE) break
  }
  return chosen
}

module.exports = { FIXED_IN, EOL_BRANCHES, VERDICT, EXIT_CODE, versionStatus, extractVersion }
