const { encrypt, decrypt } = require("./index.node");
//
// Stubbed out funcs that will be implemented in Rust and live in ./lib
//

function cipherNew() {
  return "cipher" as const;
}

// function encrypt(
//   plaintextPayload: PlaintextEqlPayload
// ): Promise<EncryptedEqlPayload> {
//   return new Promise((resolve) => {
//     resolve({ c: `${plaintextPayload.plaintext}-encrypted` });
//   });
// }

// function decrypt(
//   field: EqlField,
//   encryptedPayload: EncryptedEqlPayload
// ): Promise<PlaintextEqlPayload> {
//   return new Promise((resolve) => {
//     const plaintext = encryptedPayload.c.replace("-encrypted", "");
//     resolve(newPlaintextPayload(field, plaintext));
//   });
// }

//
// This part will live in wrapper TS code (e.g. jseql).
//

type Eql = {
  cipher: "cipher"; // TODO: actual Cipher
  field: (opts: FieldOpts) => EqlField;
};

type FieldOpts = {
  table: string;
  column: string;
};

type EqlField = {
  cipher: any;
  table: string;
  column: string;
  plaintextPayload: (plaintext: string) => PlaintextEqlPayload;
  decrypt: (
    encryptedPayload: EncryptedEqlPayload
  ) => Promise<PlaintextEqlPayload>;
};

type EncryptedEqlPayload = {
  c: string;
};

type PlaintextEqlPayload = {
  plaintext: string;
  field: EqlField;
  encrypt: () => Promise<EncryptedEqlPayload>;
};

function eql(): Eql {
  return {
    cipher: cipherNew(),
    field(opts: FieldOpts): EqlField {
      return {
        cipher: this.cipher,
        table: opts.table,
        column: opts.column,
        plaintextPayload(plaintext: string): PlaintextEqlPayload {
          return newPlaintextPayload(this, plaintext);
        },
        decrypt(
          encryptedPayload: EncryptedEqlPayload
        ): Promise<PlaintextEqlPayload> {
          // return decrypt(this, encryptedPayload);

          return decrypt(encryptedPayload.c).then((val: string) =>
            newPlaintextPayload(this, val)
          );
        },
      };
    },
  };
}

function newPlaintextPayload(
  field: EqlField,
  plaintext: string
): PlaintextEqlPayload {
  return {
    plaintext,
    field,
    encrypt(): Promise<EncryptedEqlPayload> {
      // return encrypt(this);

      return encrypt(this.plaintext).then((val: string) => {
        return { c: val };
      });
    },
  };
}

//
// Example code using the new interface
//

const eqlClient = eql();

export const emailField = eqlClient.field({
  table: "users",
  column: "email",
});

(async () => {
  const encryptedEmail = await emailField.plaintextPayload("abc").encrypt();

  console.log(encryptedEmail); // { c: "abc-encrypted" }

  const decrypted = await emailField.decrypt(encryptedEmail);

  console.log(decrypted.plaintext); // "abc"
})();

//
// Misc. scribbling for the interface
//

/*
EqlField
{
  cipher: Cipher,
  table: string,
  column: string,
  encrypt: (PlaintextEqlPayload) => Promise<EncryptedEqlPayload>,
  encryptMany: (PlaintextEqlPayload[]) => Promise<EncryptedEqlPayload[]>,
  decrypt: (EncryptedEqlPayload) => Promise<PlaintextEqlPayload>,
  decryptMany: (EncryptedEqlPayload[]) => Promise<PlaintextEqlPayload[]>,
  eqlPayload: (string) => PlaintextEqlPayload,
}

PlaintextEqlPayload
{
  plaintext: string // string works to start, but can accept multiple types later
  field: EqlField,
  withIdentity: () => PlaintextEqlPayload,
  lockTo: () => PlaintextEqlPayload,
  encrypt: () => Promise<EncryptedEqlPayload>
}

*/

// Encrypt single
// const encryptedEmail = await emailField.eqlPayload("abc").encrypt(); // => Promise<EncryptedEqlPayload>

// const encryptedEmails = await emailField.encryptMany([
//   emailField.eqlPayload("abc"),
//   emailField.eqlPayload("def"),
// ]);
