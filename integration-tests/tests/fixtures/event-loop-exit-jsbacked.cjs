// Fixture for the "event loop exits naturally" integration test.
//
// Creates a Client using a JS-supplied `opts.strategy`, performs one
// encrypt + decrypt, then returns. Does NOT call process.exit(). If the
// Node event loop drains correctly, this script terminates on its own;
// if anything (e.g. an unref'd auth Channel) is still pinning libuv,
// the parent test times out and kills it.

require('dotenv/config')
const { newClient, encrypt, decrypt } = require('@cipherstash/protect-ffi')

const encryptConfig = {
  v: 1,
  tables: {
    users: {
      email: {
        cast_as: 'string',
        indexes: { unique: {} },
      },
    },
  },
}

;(async () => {
  // Use the wasm-inline build of @cipherstash/auth — it has no native
  // binary dep, works on any Node target, and lets us exercise the
  // `opts.strategy` (JsBacked) code path with a real getToken.
  // Note: stack-auth 0.36 dropped CS_REGION in favour of CS_WORKSPACE_CRN;
  // the wasm AccessKeyStrategy.create still takes a region string as its
  // first argument (named that way in the .d.ts) but expects the
  // <region>.<provider> form, which is the middle segment of a CRN like
  // `crn:ap-southeast-2.aws:<workspace>`.
  const { AccessKeyStrategy } = await import('@cipherstash/auth/wasm-inline')
  const accessKey = process.env.CS_CLIENT_ACCESS_KEY
  const workspaceCrn = process.env.CS_WORKSPACE_CRN
  if (!accessKey || !workspaceCrn) {
    throw new Error(
      'event-loop-exit-jsbacked fixture needs CS_CLIENT_ACCESS_KEY and CS_WORKSPACE_CRN',
    )
  }
  const match = workspaceCrn.match(/^crn:([^:]+):/)
  if (!match) {
    throw new Error(`unexpected CS_WORKSPACE_CRN format: ${workspaceCrn}`)
  }
  const region = match[1]
  const strategy = AccessKeyStrategy.create(region, accessKey)

  const client = await newClient({ encryptConfig, strategy })

  const ciphertext = await encrypt(client, {
    plaintext: 'event-loop-exit-test@example.com',
    table: 'users',
    column: 'email',
  })

  const plaintext = await decrypt(client, { ciphertext })
  if (plaintext !== 'event-loop-exit-test@example.com') {
    console.error(`round-trip mismatch: got ${plaintext}`)
    process.exitCode = 2
    return
  }

  // No explicit process.exit(). The presence of an unref'd auth Channel
  // (the fix under test) is what lets Node terminate cleanly here.
  console.log('ok')
})().catch((err) => {
  console.error(err)
  process.exitCode = 1
})
