import { expect, test } from "vitest";

import { newClient, encrypt, decrypt } from "@cipherstash/protect-ffi"

test("can round-trip encrypt and decrypt", async () => {
  const encryptConfig = {
    v: 1,
    tables: {
      users: {
        email: {
          indexes: {
            ore: {},
            match: {},
            unique: {},
          },
        },
      },
    },
  };

  const client = await newClient(
    JSON.stringify(encryptConfig)
  );

  const ciphertext = await encrypt(client, "abc", "email", "users");

  const plaintext = await decrypt(client, JSON.parse(ciphertext).c);

  expect(plaintext).toBe("abc");
});
