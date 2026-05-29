#!/usr/bin/env node
// Promote the `[Unreleased]` section of CHANGELOG.md to a dated release entry
// for the version currently being released.
//
// Invoked from the `version` npm lifecycle hook (see package.json), so it runs
// automatically during `npm version` — both in CI releases and local bumps —
// after the package version has been bumped but before the version commit. The
// hook's trailing `git add .` stages the result into that commit, so the tag
// always carries an up-to-date CHANGELOG.
//
// Defensive by design: anything unexpected (no version, no `[Unreleased]`
// heading, already-promoted) logs and exits 0 so a release is never blocked.
import { readFileSync, writeFileSync } from 'node:fs'

const REPO = 'https://github.com/cipherstash/protectjs-ffi'
const FILE = 'CHANGELOG.md'

const version = (
  process.env.npm_package_version ||
  process.argv[2] ||
  ''
).replace(/^v/, '')
if (!version) {
  console.warn(
    'changelog-release: no version (npm_package_version unset) — skipping',
  )
  process.exit(0)
}

let text = readFileSync(FILE, 'utf8')

if (text.includes(`## [${version}]`)) {
  console.log(`changelog-release: [${version}] already present — skipping`)
  process.exit(0)
}

// Capture everything under `## [Unreleased]` up to the next `## [` section
// heading or the link-reference block at the bottom.
const unreleasedRe =
  /## \[Unreleased\]\n([\s\S]*?)(?=\n## \[|\n\[Unreleased\]:|$)/
const match = text.match(unreleasedRe)
if (!match) {
  console.warn('changelog-release: no [Unreleased] section — skipping')
  process.exit(0)
}

const body = match[1].trim() || '- _No notable changes documented._'
const today = new Date().toISOString().slice(0, 10)

// Previous released version = first `## [x.y.z]` heading (the topmost release).
const prevMatch = text.match(/## \[(\d+\.\d+\.\d+)\]/)
const prev = prevMatch ? prevMatch[1] : null

// Reset `[Unreleased]` to empty and insert the promoted, dated section below it.
text = text.replace(
  unreleasedRe,
  `## [Unreleased]\n\n## [${version}] - ${today}\n\n${body}\n`,
)

// Point the `[Unreleased]` compare link at the new tag, and add a link for the
// freshly promoted version directly beneath it.
const newLink = `[${version}]: ${REPO}/compare/${prev ? `v${prev}` : `v${version}^`}...v${version}`
text = text
  .replace(
    /\[Unreleased\]:.*/,
    `[Unreleased]: ${REPO}/compare/v${version}...HEAD`,
  )
  .replace(/(\[Unreleased\]:.*\n)/, `$1${newLink}\n`)

writeFileSync(FILE, text)
console.log(
  `changelog-release: promoted [Unreleased] -> [${version}] - ${today}`,
)
