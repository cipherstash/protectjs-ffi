use cipherstash_client::encryption::{EncryptedSteVecTerm, SteQueryVec, TokenizedSelector};
use serde::Serialize;

#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum Query {
    Json(SteQueryVec<16>),
    SteVecSelector(TokenizedSelector<16>),
    SteVecTerm(EncryptedSteVecTerm),
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
        let x = indexer().query(json!({"foo": 1}), &index_key()).map(Query::Json).unwrap();
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