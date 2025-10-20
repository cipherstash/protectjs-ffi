use cipherstash_client::{encryption::{self, EncryptedEntry, EncryptionError, IndexTerm, SteVec}, zerokms::{self, encrypted_record, EncryptedRecord}};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{encrypt_config::Identifier, Error};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "k")]
pub enum Encrypted {
    /// A standard EQL payload containing an encrypted record and optional indexes.
    #[serde(rename = "ct")]
    Ciphertext {
        #[serde(rename = "c", with = "encrypted_record::formats::mp_base85")]
        ciphertext: EncryptedRecord,
        #[serde(rename = "ob")]
        ore_index: Option<Vec<String>>,
        #[serde(rename = "bf")]
        match_index: Option<Vec<u16>>,
        #[serde(rename = "hm")]
        unique_index: Option<String>,
        #[serde(rename = "i")]
        identifier: Identifier,
        #[serde(rename = "v")]
        version: u16,
    },

    /// A SteVec index payload for storage of SteVec indexes.
    #[serde(rename = "sv")]
    SteVec {
        #[serde(rename = "sv")]
        ste_vec_index: SteVec<16>,
        #[serde(rename = "i")]
        identifier: Identifier,
        #[serde(rename = "v")]
        version: u16,
    },

    /// A single SteVec entry.
    /// This is useful when returning individual entries from queries and wanting to decrypt them.
    #[serde(rename = "sve")]
    SteVecEntry {
        #[serde(rename = "sve")]
        entry: EncryptedEntry<16>,
    }
}

impl zerokms::Decryptable for Encrypted {
    type Error = EncryptionError;

    fn keyset_id(&self) -> Option<Uuid> {
        match self {
            Self::Ciphertext { ciphertext, .. } => ciphertext.keyset_id,
            Self::SteVec { ste_vec_index, .. } => ste_vec_index.root_ciphertext().ok().and_then(|ct| ct.keyset_id()),
            Self::SteVecEntry { entry } => entry.record.keyset_id(),
        }
    }

    fn into_encrypted_record(self) -> Result<EncryptedRecord, Self::Error> {
        match self {
            Self::Ciphertext { ciphertext, .. } => Ok(ciphertext),
            Self::SteVec { ste_vec_index, .. } => ste_vec_index.into_root_ciphertext(),
            Self::SteVecEntry { entry } => Ok(entry.record),
        }
    }

    fn retrieve_key_payload<'a>(&'a self) -> Result<zerokms::RetrieveKeyPayload<'a>, Self::Error> {
        match self {
            Self::Ciphertext { ciphertext, .. } => ciphertext.retrieve_key_payload().map_err(EncryptionError::from),
            Self::SteVec { ste_vec_index, .. } => ste_vec_index.root_ciphertext()?.retrieve_key_payload().map_err(EncryptionError::from),
            Self::SteVecEntry { entry } => entry.record.retrieve_key_payload().map_err(EncryptionError::from),
        }
    }
}

impl TryFrom<(encryption::Encrypted, &Identifier)> for Encrypted {
    type Error = Error;

    fn try_from((encrypted, identifier): (encryption::Encrypted, &Identifier)) -> Result<Self, Self::Error> {
        match encrypted {
            encryption::Encrypted::Record(ciphertext, terms) => {
                struct Indexes {
                    match_index: Option<Vec<u16>>,
                    ore_index: Option<Vec<String>>,
                    unique_index: Option<String>,
                }

                let mut indexes = Indexes {
                    match_index: None,
                    ore_index: None,
                    unique_index: None,
                };

                for index_term in terms {
                    match index_term {
                        IndexTerm::Binary(bytes) => {
                            indexes.unique_index = Some(format_index_term_binary(&bytes))
                        }
                        IndexTerm::BitMap(inner) => indexes.match_index = Some(inner),
                        IndexTerm::OreArray(vec_of_bytes) => {
                            indexes.ore_index = Some(format_index_term_ore_array(&vec_of_bytes));
                        }
                        IndexTerm::OreFull(bytes) => {
                            indexes.ore_index = Some(format_index_term_ore(&bytes));
                        }
                        IndexTerm::OreLeft(bytes) => {
                            indexes.ore_index = Some(format_index_term_ore(&bytes));
                        }
                        IndexTerm::Null => {}
                        term => return Err(Error::Unimplemented(format!("index term `{term:?}`"))),
                    };
                }

                Ok(Encrypted::Ciphertext {
                    ciphertext,
                    identifier: identifier.to_owned(),
                    match_index: indexes.match_index,
                    ore_index: indexes.ore_index,
                    unique_index: indexes.unique_index,
                    version: 2,
                })
            }
            encryption::Encrypted::SteVec(ste_vec_index) => Ok(Encrypted::SteVec {
                identifier: identifier.to_owned(),
                ste_vec_index,
                version: 2,
            }),
        }
    }
}

fn format_index_term_binary(bytes: &Vec<u8>) -> String {
    hex::encode(bytes)
}

fn format_index_term_ore_bytea(bytes: &Vec<u8>) -> String {
    hex::encode(bytes)
}

///
/// Formats a Vec<Vec<u8>> into a Vec<String>
///
fn format_index_term_ore_array(vec_of_bytes: &[Vec<u8>]) -> Vec<String> {
    vec_of_bytes
        .iter()
        .map(format_index_term_ore_bytea)
        .collect()
}

///
/// Formats a Vec<Vec<u8>> into a single elenent Vec<String>
///
fn format_index_term_ore(bytes: &Vec<u8>) -> Vec<String> {
    vec![format_index_term_ore_bytea(bytes)]
}

#[cfg(test)]
mod tests {
    use super::*;

    mod deserialize {
        use super::*;

        #[test]
        fn ste_vec_entry() {
            let json_data = serde_json::json!({
                "k": "sve",
                "sve": {
                    "c": "mBbKmZYAVzP6EORkHe`E;VK=(7eXEXplEbxc8;TAEw#iE0n~Ic#Kd6J#2^_sVQ9%b&$!kU_5n2v@s81UBmm7(>-mWRlY|7j7Pg?k",
                    "s": "d18aa290a20cf6413f50d5ca87a0a6c2",
                    "ocv": "026d08ef26fd0fb009277f9583fd123f74fae53bc10d5fc00e",
                    "parent_is_array": false
                }
            });
            let deserialized: Result<Encrypted, _> = serde_json::from_value(json_data);
            println!("deserialized: {:?}", deserialized);
            assert!(deserialized.is_ok());
        }
    }
}