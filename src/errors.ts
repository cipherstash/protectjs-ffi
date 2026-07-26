/**
 * Every code an error crossing the FFI boundary can carry.
 *
 * Declared once, as a value, with the type derived from it — a hand-written
 * union alongside a hand-written runtime list is two things to keep in step,
 * and this list already has to agree with a third: the
 * `#[diagnostic(code(..))]` attributes on `Error` in
 * `crates/protect-ffi/src/lib.rs`, which is where the codes are decided.
 * `errorCodes.test.ts` reads that file and proves the two agree.
 *
 * `UNKNOWN` is the exception: it is a JS-side fallback, not something Rust
 * emits. An error with no code of its own — the `#[error(transparent)]`
 * wrappers around cipherstash-client failures — simply arrives without the
 * field.
 */
export const PROTECT_ERROR_CODES = [
  'INVARIANT_VIOLATION',
  'UNKNOWN_QUERY_OP',
  'UNKNOWN_COLUMN',
  'MISSING_INDEX',
  'INVALID_QUERY_INPUT',
  'SHORT_MATCH_NEEDLE',
  'INVALID_JSON_PATH',
  'STE_VEC_REQUIRES_JSON_CAST_AS',
  'MATCH_REQUIRES_TEXT',
  'UNSUPPORTED_CONFIG_VERSION',
  'INVALID_EQL_VERSION',
  'EQL_V3_UNSUPPORTED_COLUMN',
  'EQL_V3_CONVERSION_FAILED',
  'INVALID_CIPHERTEXT',
  'UNKNOWN',
] as const

export type ProtectErrorCode = (typeof PROTECT_ERROR_CODES)[number]

const KNOWN_CODES: ReadonlySet<string> = new Set(PROTECT_ERROR_CODES)

/**
 * True when `value` is one of this library's error codes.
 *
 * Worth having because reading `err.code` structurally is otherwise
 * indiscriminate: Node puts a `code` on its own errors too, so an
 * `ECONNRESET` would pass for a {@link ProtectErrorCode} to anything that
 * checked only for the field's presence.
 */
export function isProtectErrorCode(value: unknown): value is ProtectErrorCode {
  return typeof value === 'string' && KNOWN_CODES.has(value)
}

export class ProtectError extends Error {
  code: ProtectErrorCode
  details?: unknown
  cause?: unknown

  constructor(opts: {
    code: ProtectErrorCode
    message: string
    details?: unknown
    cause?: unknown
  }) {
    super(opts.message)
    this.name = 'ProtectError'
    this.code = opts.code
    this.details = opts.details
    this.cause = opts.cause
  }
}

/**
 * Re-throw an error from the native binding as a {@link ProtectError} when it
 * carries a code.
 *
 * The code is now read off the error rather than inferred from it. Until #146
 * this ran the message through a table of fourteen prefixes and substrings to
 * guess one, three of which matched wording owned by cipherstash-config — so
 * an upstream reword would silently downgrade a caller's error to `UNKNOWN`,
 * with nothing in this repo failing. Rust attaches `err.code` at both
 * boundaries.
 *
 * An error with no recognised code is returned untouched rather than wrapped in
 * a `ProtectError` with a made-up one — the same choice the old code made when
 * its table did not match.
 */
export function normalizeError(err: unknown): unknown {
  if (err instanceof ProtectError) {
    return err
  }

  if (err === null || typeof err !== 'object') {
    return err
  }

  const { code, message } = err as { code?: unknown; message?: unknown }
  if (!isProtectErrorCode(code)) {
    return err
  }

  return new ProtectError({
    code,
    message: String(message ?? 'Unknown error'),
    cause: err,
  })
}
