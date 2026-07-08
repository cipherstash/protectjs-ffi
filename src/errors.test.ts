import { describe, expect, it } from 'vitest'
import { inferErrorCode, normalizeError, ProtectError } from './errors.js'

describe('inferErrorCode', () => {
  it('maps invariant violations', () => {
    expect(
      inferErrorCode('protect-ffi invariant violation: something impossible'),
    ).toBe('INVARIANT_VIOLATION')
  })

  it('maps unknown query operations', () => {
    expect(inferErrorCode('Unknown query operation: frobnicate')).toBe(
      'UNKNOWN_QUERY_OP',
    )
  })

  it('maps EQL v3 query errors', () => {
    expect(
      inferErrorCode(
        'EQL v3 scalar query wire shape is not defined; use eqlVersion 2',
      ),
    ).toBe('EQL_V3_QUERY_UNSUPPORTED')
    expect(
      inferErrorCode('EQL v3 selector query wire shape is not defined'),
    ).toBe('EQL_V3_QUERY_UNSUPPORTED')
  })

  it('maps invalid eqlVersion errors', () => {
    // Mirrors the Rust `Invalid eqlVersion {0}: expected 2 or 3` message.
    expect(inferErrorCode('Invalid eqlVersion 4: expected 2 or 3')).toBe(
      'INVALID_EQL_VERSION',
    )
  })

  it('maps EQL v3 unsupported-column errors', () => {
    // Mirrors the Rust `Column '{column}' cannot be represented in EQL v3: {reason}. {hint}` message.
    expect(
      inferErrorCode(
        "Column 'users.email' cannot be represented in EQL v3: no v3 domain for this cast_as. Use eqlVersion 2.",
      ),
    ).toBe('EQL_V3_UNSUPPORTED_COLUMN')
  })

  it('maps EQL v3 conversion failures', () => {
    expect(inferErrorCode('EQL v3 conversion failed: bad payload')).toBe(
      'EQL_V3_CONVERSION_FAILED',
    )
  })

  it('maps invalid EQL ciphertext errors', () => {
    expect(
      inferErrorCode('Invalid EQL ciphertext: could not parse mp_base85'),
    ).toBe('INVALID_CIPHERTEXT')
  })

  it('falls back to UNKNOWN for unrecognized messages', () => {
    expect(inferErrorCode('something else entirely')).toBe('UNKNOWN')
  })
})

describe('normalizeError', () => {
  it('wraps invalid EQL ciphertext errors as ProtectError', () => {
    const raw = new Error('Invalid EQL ciphertext: could not parse mp_base85')

    const result = normalizeError(raw)

    expect(result).toBeInstanceOf(ProtectError)
    const err = result as ProtectError
    expect(err.code).toBe('INVALID_CIPHERTEXT')
    expect(err.message).toBe(
      'Invalid EQL ciphertext: could not parse mp_base85',
    )
    expect(err.cause).toBe(raw)
  })

  it('returns ProtectError instances unchanged', () => {
    const original = new ProtectError({
      code: 'UNKNOWN_COLUMN',
      message: 'column "email" not found in Encrypt config',
    })

    expect(normalizeError(original)).toBe(original)
  })

  it('returns unrecognized errors unchanged', () => {
    const raw = new Error('something else entirely')

    expect(normalizeError(raw)).toBe(raw)
  })
})
