//! Print the self-contained EQL v3 install SQL bundled with the locked
//! `eql-bindings` release to stdout.
//!
//! Used by the integration-tests `eql:v3:build` mise task to regenerate the
//! committed snapshot (`integration-tests/sql/cipherstash-encrypt-v3.sql`),
//! so the SQL the tests install is exactly the release the Rust conversion
//! code links against — no sibling-checkout / branch drift possible.

fn main() {
    print!("{}", eql_bindings::sql::INSTALL_SQL);
}
