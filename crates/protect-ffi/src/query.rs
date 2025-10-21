use cipherstash_client::{encryption::{EncryptedSteVecTerm, IndexTerm, SteQueryVec, TokenizedSelector}};
use serde::Serialize;

/// Represents a query term that can be serialized to JSON for use in FFI.
#[derive(Serialize, Debug)]
pub enum Query {
    #[serde(rename = "hm", with = "const_hex_sans_prefix")]
    Binary(Vec<u8>),
    #[serde(rename = "bf")]
    BitMap(Vec<u16>),

    #[serde(rename = "ob")]
    OreLeft(Vec<OreTerm>),

    // NOTE: This type doesn't current exist in the EQL spec but its convenient to give it the sv name
    // even though its the query type and not the full encrypted entry.
    #[serde(rename = "sv")]
    SteQuery(SteQueryVec<16>),
    
    #[serde(rename = "s")]
    SteVecSelector(TokenizedSelector<16>),

    SteVecTerm(EncryptedSteVecTerm),
}

#[derive(Serialize, Debug)]
#[serde(transparent)]
pub struct OreTerm(#[serde(with = "const_hex_sans_prefix")] Vec<u8>);

impl TryFrom<IndexTerm> for Query {
    type Error = String;

    fn try_from(value: IndexTerm) -> Result<Self, Self::Error> {
        match value {
            IndexTerm::Binary(b) => Ok(Query::Binary(b)),
            IndexTerm::BitMap(bm) => Ok(Query::BitMap(bm)),
            IndexTerm::OreLeft(ol) => Ok(Query::OreLeft(vec![OreTerm(ol)])),
            IndexTerm::OreFull(of) => Ok(Query::OreLeft(vec![OreTerm(of)])),
            IndexTerm::SteQueryVec(sqv) => Ok(Query::SteQuery(sqv)),
            IndexTerm::SteVecSelector(ts) => Ok(Query::SteVecSelector(ts)),
            IndexTerm::SteVecTerm(est) => Ok(Query::SteVecTerm(est)),
            unsupported => Err(format!("{unsupported:?} cannot be converted to Query")),
        }
    }
}

// The const_hex provides a serde serializer but it prefixes with "0x" which we don't want here.
mod const_hex_sans_prefix {
    use serde::Serializer;

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = const_hex::encode(bytes);
        serializer.serialize_str(&hex_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherstash_client::ejsonpath::Selector;
    use cipherstash_client::encryption::{JsonIndexer, JsonIndexerOptions};
    use cipherstash_client::zerokms::IndexKey;
    use serde_json::json;

    fn indexer() -> JsonIndexer {
        let opts = JsonIndexerOptions { prefix: "foo".to_string() };
        JsonIndexer::new(opts)
    }

    fn index_key() -> IndexKey {
        [0u8; 32].into()
    }

    #[test]
    fn serialize_ste_query_vec() {
        let x = indexer().query(json!({"foo": 1}), &index_key()).map(Query::SteQuery).unwrap();
        let check = json!([
            [
                "814586efb4a86da0ae72f65c87e4b7b3",
                "001550590d76040654f5dcf654adfd52da"
            ],
            [
                "9d1dbec87dd19ab2217426e87d91db06",
                "019d5739400872d8378c4002bd922ad7ff296fd9124a8cbfbf64e4803fa6e21d0f8cf8376a034d2735759c7b8e9f39d519b1da4264726e977e2d2df4ccf1b8c41d"
            ]
        ]);

        assert_eq!(serde_json::to_value(&x).unwrap(), check);
    }

    #[test]
    fn serialize_ste_vec_selector() {
        let selector = Selector::parse("$.foo").unwrap();
        let tokenized_selector = Query::SteVecSelector(indexer().generate_selector(selector, &index_key()));
        assert_eq!(serde_json::to_value(&tokenized_selector).unwrap(), json!("9d1dbec87dd19ab2217426e87d91db06"));
    }

    #[test]
    fn serialize_ste_vec_term() {
        
    }
}