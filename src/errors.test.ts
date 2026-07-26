import { describe, expect, it } from 'vitest'
import {
  PROTECT_ERROR_CODES,
  ProtectError,
  isProtectErrorCode,
  normalizeError,
} from './errors.js'

describe('isProtectErrorCode', () => {
  it('accepts every declared code', () => {
    for (const code of PROTECT_ERROR_CODES) {
      expect(isProtectErrorCode(code)).toBe(true)
    }
  })

  it('rejects a Node error code', () => {
    // Why this predicate exists: `err.code` is not ours alone. Reading the
    // field structurally without checking the value would let a socket failure
    // surface to a caller as a ProtectError.
    expect(isProtectErrorCode('ECONNRESET')).toBe(false)
    expect(isProtectErrorCode('ERR_INVALID_ARG_TYPE')).toBe(false)
  })

  it('rejects non-strings', () => {
    expect(isProtectErrorCode(undefined)).toBe(false)
    expect(isProtectErrorCode(null)).toBe(false)
    expect(isProtectErrorCode(42)).toBe(false)
    expect(isProtectErrorCode({ toString: () => 'UNKNOWN_COLUMN' })).toBe(false)
  })
})

describe('normalizeError', () => {
  it('wraps an error carrying a code', () => {
    // What the bindings throw: a JS Error with `code` set by Rust from the
    // variant's `#[diagnostic(code(..))]`.
    const raw = Object.assign(
      new Error('Invalid EQL ciphertext: could not parse mp_base85'),
      { code: 'INVALID_CIPHERTEXT' },
    )

    const result = normalizeError(raw)

    expect(result).toBeInstanceOf(ProtectError)
    const err = result as ProtectError
    expect(err.code).toBe('INVALID_CIPHERTEXT')
    expect(err.message).toBe(
      'Invalid EQL ciphertext: could not parse mp_base85',
    )
    expect(err.cause).toBe(raw)
  })

  it('leaves an error with no code alone', () => {
    // The `#[error(transparent)]` variants carry no code, so nothing is
    // attached and there is nothing to promote. Before #146 this case was
    // decided by whether a substring table happened to match upstream wording.
    const raw = new Error('some cipherstash-client failure')

    expect(normalizeError(raw)).toBe(raw)
  })

  it('does not promote a foreign code', () => {
    const raw = Object.assign(new Error('connection reset'), {
      code: 'ECONNRESET',
    })

    expect(normalizeError(raw)).toBe(raw)
  })

  it('returns ProtectError instances unchanged', () => {
    const original = new ProtectError({
      code: 'UNKNOWN_COLUMN',
      message: 'column "email" not found in Encrypt config',
    })

    expect(normalizeError(original)).toBe(original)
  })

  it('passes non-objects through', () => {
    expect(normalizeError('a thrown string')).toBe('a thrown string')
    expect(normalizeError(null)).toBe(null)
    expect(normalizeError(undefined)).toBe(undefined)
  })

  it('survives an error whose message is missing', () => {
    const raw = { code: 'MISSING_INDEX' }

    const err = normalizeError(raw) as ProtectError
    expect(err).toBeInstanceOf(ProtectError)
    expect(err.message).toBe('Unknown error')
  })
})

describe('no message-shape routing', () => {
  // One message per pattern the deleted `inferErrorCode` table matched on.
  // Each used to be enough on its own to produce a code; none is now. This is
  // the regression that would mean the string matching had crept back — most
  // plausibly as a "fallback for errors that arrive without a code", which is
  // the same guess in a smaller box.
  const OLD_TABLE_MESSAGES = [
    'protect-ffi invariant violation: something impossible',
    "Unknown query operation: 'frobnicate'",
    "Invalid query input for 'match': received number, expected string.",
    "Invalid match query on column 'email': tokenizes to nothing.",
    "Invalid JSON path 'name': not a path.",
    'column users.email not found in Encrypt config',
    "Column 'email' does not have a 'match' index configured.",
    'ste_vec index on users.meta requires plaintext_type: json (found text)',
    'match index on users.age requires plaintext_type: text (found int)',
    'unsupported config version: 2 (expected 1)',
    'Invalid eqlVersion 4: expected 2 or 3',
    "Column 'users.email' cannot be represented in EQL v3: no v3 domain.",
    'EQL v3 conversion failed: bad payload',
    'Invalid EQL ciphertext: could not parse mp_base85',
  ]

  it.each(OLD_TABLE_MESSAGES)('does not infer a code from %j', (message) => {
    const raw = new Error(message)

    expect(normalizeError(raw)).toBe(raw)
  })
})
