export type ProtectErrorCode =
  | 'INVARIANT_VIOLATION'
  | 'UNKNOWN_QUERY_OP'
  | 'UNKNOWN_COLUMN'
  | 'MISSING_INDEX'
  | 'INVALID_QUERY_INPUT'
  | 'SHORT_MATCH_NEEDLE'
  | 'INVALID_JSON_PATH'
  | 'STE_VEC_REQUIRES_JSON_CAST_AS'
  | 'MATCH_REQUIRES_TEXT'
  | 'UNSUPPORTED_CONFIG_VERSION'
  | 'INVALID_EQL_VERSION'
  | 'EQL_V3_UNSUPPORTED_COLUMN'
  | 'EQL_V3_CONVERSION_FAILED'
  | 'INVALID_CIPHERTEXT'
  | 'UNKNOWN'

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

export function inferErrorCode(message: string): ProtectErrorCode {
  if (message.startsWith('protect-ffi invariant violation:')) {
    return 'INVARIANT_VIOLATION'
  }
  if (message.startsWith('Unknown query operation:')) {
    return 'UNKNOWN_QUERY_OP'
  }
  if (message.startsWith('Invalid query input for')) {
    return 'INVALID_QUERY_INPUT'
  }
  if (message.startsWith('Invalid match query on column')) {
    return 'SHORT_MATCH_NEEDLE'
  }
  if (message.startsWith('Invalid JSON path')) {
    return 'INVALID_JSON_PATH'
  }
  if (message.includes(' not found in Encrypt config')) {
    return 'UNKNOWN_COLUMN'
  }
  if (message.includes(' index configured')) {
    return 'MISSING_INDEX'
  }
  if (message.includes('requires plaintext_type: json')) {
    return 'STE_VEC_REQUIRES_JSON_CAST_AS'
  }
  if (message.includes('requires plaintext_type: text')) {
    return 'MATCH_REQUIRES_TEXT'
  }
  if (message.includes('unsupported config version')) {
    return 'UNSUPPORTED_CONFIG_VERSION'
  }
  if (message.startsWith('Invalid eqlVersion')) {
    return 'INVALID_EQL_VERSION'
  }
  if (message.includes('cannot be represented in EQL v3')) {
    return 'EQL_V3_UNSUPPORTED_COLUMN'
  }
  if (message.startsWith('EQL v3 conversion failed')) {
    return 'EQL_V3_CONVERSION_FAILED'
  }
  if (message.startsWith('Invalid EQL ciphertext:')) {
    return 'INVALID_CIPHERTEXT'
  }
  return 'UNKNOWN'
}

export function normalizeError(err: unknown): unknown {
  if (err instanceof ProtectError) {
    return err
  }

  if (err && typeof err === 'object' && 'message' in err) {
    const message = String(
      (err as { message?: unknown }).message ?? 'Unknown error',
    )
    const code = inferErrorCode(message)
    if (code !== 'UNKNOWN') {
      return new ProtectError({ code, message, cause: err })
    }
  }

  return err
}
