#!/usr/bin/env node
// Print the CHANGELOG.md section body for a given version, for use as GitHub
// release notes. Usage: node scripts/changelog-extract.mjs 0.26.0
//
// Exits non-zero if the section is missing so the caller can fall back to a
// generic body rather than publishing an empty release.
import { readFileSync } from 'node:fs'

const version = (process.argv[2] || '').replace(/^v/, '')
if (!version) {
  console.error('usage: changelog-extract.mjs <version>')
  process.exit(2)
}

let text
try {
  text = readFileSync('CHANGELOG.md', 'utf8')
} catch (err) {
  // A missing/unreadable file (or wrong cwd) should read as "no notes here"
  // — a concise message and non-zero exit so the caller falls back cleanly,
  // not a raw stack trace.
  console.error(
    `changelog-extract: could not read CHANGELOG.md (${err.message})`,
  )
  process.exit(1)
}
// Escape every regex metacharacter — semver pre-release/build tags can contain
// `+`, `.` and other special chars — so the heading is matched literally.
const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
// Match the version heading, then capture until the next `## [` section or the
// link-reference block (`[x]: ...`) at the bottom. `\r?\n` tolerates CRLF files.
const re = new RegExp(
  `## \\[${escaped}\\][^\\r\\n]*\\r?\\n([\\s\\S]*?)(?=\\r?\\n## \\[|\\r?\\n\\[[^\\]]+\\]:|$)`,
)
const match = text.match(re)
if (!match) {
  console.error(`changelog-extract: no section for ${version}`)
  process.exit(1)
}

process.stdout.write(`${match[1].trim()}\n`)
