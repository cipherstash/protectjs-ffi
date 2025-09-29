use cipherstash_client::encryption::{Plaintext, TypeParseError, TryFromPlaintext};
use serde::{Deserialize, Serialize};
use vitaminc_protected::OpaqueDebug;

#[derive(Deserialize, Serialize, OpaqueDebug, PartialEq)]
#[serde(untagged)]
pub(crate) enum JsPlaintext {
    String(String),
    Number(f64),
    Boolean(bool),
    JsonB(serde_json::Value),
}

impl From<JsPlaintext> for Plaintext {
    fn from(value: JsPlaintext) -> Self {
        match value {
            JsPlaintext::String(s) => Plaintext::Utf8Str(Some(s)),
            JsPlaintext::Number(n) => Plaintext::Float(Some(n)),
            JsPlaintext::Boolean(b) => Plaintext::Boolean(Some(b)),
            JsPlaintext::JsonB(j) => Plaintext::JsonB(Some(j)),
        }
    }
}

impl TryFrom<Plaintext> for JsPlaintext {
    type Error = TypeParseError;

    fn try_from(value: Plaintext) -> Result<Self, Self::Error> {
        match value {
            v @ Plaintext::Utf8Str(Some(_)) => String::try_from_plaintext(v).map(JsPlaintext::String),
            v @ Plaintext::JsonB(Some(_)) => serde_json::Value::try_from_plaintext(v).map(JsPlaintext::JsonB),
            // Note: BigInt is converted to f64, which may lose precision for very large integers
            // let this be a reminder of JavaScript's limitations with numbers
            Plaintext::BigInt(Some(n)) => Ok(JsPlaintext::Number(n as f64)),
            Plaintext::Float(Some(n)) => Ok(JsPlaintext::Number(n)),
            Plaintext::Boolean(Some(b)) => Ok(JsPlaintext::Boolean(b)),
            _ => Err(TypeParseError("Unsupported type".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_plaintext::JsPlaintext;

    mod js_plaintext_to_plaintext {
        use super::*;

        #[quickcheck]
        fn test_string(s: String) {
            let js_string = JsPlaintext::String(s.clone());
            let plaintext_string: Plaintext = js_string.into();
            assert_eq!(plaintext_string, Plaintext::Utf8Str(Some(s)));
        }

        #[quickcheck]
        fn test_number(f: f64) {
            let js_number = JsPlaintext::Number(f);
            let plaintext_number: Plaintext = js_number.into();
            if let Plaintext::Float(Some(n)) = plaintext_number {
                assert_eq!(n.total_cmp(&f), std::cmp::Ordering::Equal);
            } else {
                panic!("Expected Plaintext::Float variant");
            }
        }

        #[quickcheck]
        fn test_boolean(b: bool) {
            let js_boolean = JsPlaintext::Boolean(b);
            let plaintext_boolean: Plaintext = js_boolean.into();
            assert_eq!(plaintext_boolean, Plaintext::Boolean(Some(b)));
        }

        #[test]
        fn test_jsonb() {
            let js_jsonb = JsPlaintext::JsonB(serde_json::json!({"key": "value"}));
            let plaintext_jsonb: Plaintext = js_jsonb.into();
            assert_eq!(plaintext_jsonb, Plaintext::JsonB(Some(serde_json::json!({"key": "value"}))));
        }
    }

    mod plaintext_to_js_plaintext {
        use chrono::{DateTime, Utc};
        use super::*;

        #[quickcheck]
        fn test_utf8str(s: String) {
            let plaintext_string = Plaintext::Utf8Str(Some(s.clone()));
            let js_string: JsPlaintext = plaintext_string.try_into().unwrap();
            assert_eq!(js_string, JsPlaintext::String(s));
        }

        #[quickcheck]
        fn test_float(f: f64) {
            let plaintext_number = Plaintext::Float(Some(f));
            let js_number: JsPlaintext = plaintext_number.try_into().unwrap();
            if let JsPlaintext::Number(n) = js_number {
                assert_eq!(n.total_cmp(&f), std::cmp::Ordering::Equal);
            } else {
                panic!("Expected JsPlaintext::Number variant");
            }
        }

        #[quickcheck]
        fn test_boolean(b: bool) {
            let plaintext_boolean = Plaintext::Boolean(Some(b));
            let js_boolean: JsPlaintext = plaintext_boolean.try_into().unwrap();
            assert_eq!(js_boolean, JsPlaintext::Boolean(b));
        }

        #[test]
        fn test_jsonb() {
            let plaintext_jsonb = Plaintext::JsonB(Some(serde_json::json!({"key": "value"})));
            let js_jsonb: JsPlaintext = plaintext_jsonb.try_into().unwrap();
            assert_eq!(js_jsonb, JsPlaintext::JsonB(serde_json::json!({"key": "value"})));
        }

        #[quickcheck]
        fn test_bigint(i: i64) {
            let plaintext_bigint = Plaintext::BigInt(Some(i));
            let js_number: JsPlaintext = plaintext_bigint.try_into().unwrap();
            assert_eq!(js_number, JsPlaintext::Number(i as f64));
        }

        #[test]
        fn test_unsupported_type() {
            let ts: DateTime<Utc> = Utc::now();
            let plaintext_timestamp = Plaintext::Timestamp(Some(ts));
            let result: Result<JsPlaintext, TypeParseError> = plaintext_timestamp.try_into();
            assert!(result.is_err());
        }
    }
}