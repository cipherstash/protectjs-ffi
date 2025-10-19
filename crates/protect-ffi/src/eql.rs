use cipherstash_client::encryption::{self, IndexTerm, SteVec};
use serde::{Deserialize, Serialize};

use crate::{encrypt_config::Identifier, Error};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "k")]
pub enum Encrypted {
    #[serde(rename = "ct")]
    Ciphertext {
        #[serde(rename = "c")]
        ciphertext: String,
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
    #[serde(rename = "sv")]
    SteVec {
        #[serde(rename = "sv")]
        ste_vec_index: SteVec<16>,
        #[serde(rename = "i")]
        identifier: Identifier,
        #[serde(rename = "v")]
        version: u16,
    },
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

                let ciphertext = ciphertext
                    .to_mp_base85()
                    // The error type from `to_mp_base85` isn't public, so we don't derive an error for this one.
                    // Instead, we use `map_err`.
                    .map_err(|err| Error::Base85(err.to_string()))?;

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