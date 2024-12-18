const { encrypt, decrypt, newClient } = require("./index.node");

//
// This part will live in wrapper TS code (e.g. jseql).
//

type Eql = {
  client: Client;
  field: (opts: FieldOpts) => EqlField;
};

type Client = {};

type FieldOpts = {
  table: string;
  column: string;
};

type EqlField = {
  client: Client;
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

function eql(): Promise<Eql> {
  return newClient().then((client: Client) => newEql(client));
}

function newEql(client: Client): Eql {
  return {
    client,
    field(opts: FieldOpts): EqlField {
      return {
        client: this.client,
        table: opts.table,
        column: opts.column,
        plaintextPayload(plaintext: string): PlaintextEqlPayload {
          return newPlaintextPayload(this, plaintext);
        },
        decrypt(
          encryptedPayload: EncryptedEqlPayload
        ): Promise<PlaintextEqlPayload> {
          return decrypt(encryptedPayload.c, this.client).then((val: string) =>
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
      return encrypt(this.plaintext, this.field.column, this.field.client).then(
        (val: string) => {
          return { c: val };
        }
      );
    },
  };
}

//
// Example code using the new interface
//

(async () => {
  const eqlClient = await eql();

  const emailField = eqlClient.field({
    table: "users",
    column: "email",
  });

  const encryptedEmail = await emailField.plaintextPayload("abcdef").encrypt();

  console.log(encryptedEmail);

  const decrypted = await emailField.decrypt(encryptedEmail);

  console.log(decrypted.plaintext);
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
