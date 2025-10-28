use cipherstash_client::encryption::{Plaintext, TryFromPlaintext, TypeParseError};
use cipherstash_client::schema::ColumnType;
use rust_decimal::Decimal;
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
            v @ Plaintext::Utf8Str(Some(_)) => {
                String::try_from_plaintext(v).map(JsPlaintext::String)
            }
            v @ Plaintext::JsonB(Some(_)) => {
                serde_json::Value::try_from_plaintext(v).map(JsPlaintext::JsonB)
            }
            // Note: BigInt is converted to f64, which may lose precision for integers larger than
            // JavaScript's Number.MAX_SAFE_INTEGER (2^53 - 1). Only values up to this threshold
            // can be safely represented as a Number in JavaScript without loss of precision.
            Plaintext::BigInt(Some(n)) => Ok(JsPlaintext::Number(n as f64)),
            Plaintext::Float(Some(n)) => Ok(JsPlaintext::Number(n)),
            Plaintext::Boolean(Some(b)) => Ok(JsPlaintext::Boolean(b)),
            _ => Err(TypeParseError("Unsupported type".to_string())),
        }
    }
}

impl JsPlaintext {
    /// Convert JsPlaintext to Plaintext based on a target ColumnType.
    /// 
    /// This conversion follows the rule that type coercion is allowed but parsing is not.
    /// For example:
    /// - JsPlaintext::Number to Plaintext::BigInt is allowed (coercion with truncation)
    /// - JsPlaintext::String to Plaintext::BigInt is NOT allowed (would require parsing)
    pub fn to_plaintext_with_type(&self, column_type: ColumnType) -> Result<Plaintext, TypeParseError> {
        match (self, column_type) {
            // String conversions - only allow to Utf8Str
            (JsPlaintext::String(s), ColumnType::Utf8Str) => Ok(Plaintext::Utf8Str(Some(s.clone()))),
            
            // Number conversions - allow to numeric types with potential truncation/coercion
            (JsPlaintext::Number(n), ColumnType::Float) => Ok(Plaintext::Float(Some(*n))),
            (JsPlaintext::Number(n), ColumnType::Decimal) => {
                Decimal::try_from(*n)
                    .map(|d| Plaintext::Decimal(Some(d)))
                    .map_err(|e| TypeParseError(format!("Cannot convert number to Decimal: {}", e)))
            },
            (JsPlaintext::Number(n), ColumnType::BigInt) => Ok(Plaintext::BigInt(Some(*n as i64))),
            (JsPlaintext::Number(n), ColumnType::Int) => Ok(Plaintext::Int(Some(*n as i32))),
            (JsPlaintext::Number(n), ColumnType::SmallInt) => Ok(Plaintext::SmallInt(Some(*n as i16))),
            (JsPlaintext::Number(n), ColumnType::BigUInt) => {
                if *n < 0.0 {
                    Err(TypeParseError("Cannot convert negative number to BigUInt".to_string()))
                } else {
                    Ok(Plaintext::BigUInt(Some(*n as u64)))
                }
            }
            
            // Boolean conversions - only allow to Boolean
            (JsPlaintext::Boolean(b), ColumnType::Boolean) => Ok(Plaintext::Boolean(Some(*b))),
            
            // JsonB conversions - only allow to JsonB
            (JsPlaintext::JsonB(j), ColumnType::JsonB) => Ok(Plaintext::JsonB(Some(j.clone()))),
            
            // All other conversions are not allowed
            (js_type, col_type) => Err(TypeParseError(
                format!(
                    "Unsupported conversion from {:?} to {:?}",
                    js_plaintext_type_name(js_type),
                    col_type
                )
            ))
        }
    }
}

/// Helper function to get a readable type name for error messages
fn js_plaintext_type_name(js_plaintext: &JsPlaintext) -> &'static str {
    match js_plaintext {
        JsPlaintext::String(_) => "String",
        JsPlaintext::Number(_) => "Number",
        JsPlaintext::Boolean(_) => "Boolean",
        JsPlaintext::JsonB(_) => "JsonB",
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
            assert_eq!(
                plaintext_jsonb,
                Plaintext::JsonB(Some(serde_json::json!({"key": "value"})))
            );
        }
    }

    mod plaintext_to_js_plaintext {
        use super::*;
        use chrono::{DateTime, Utc};

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
            assert_eq!(
                js_jsonb,
                JsPlaintext::JsonB(serde_json::json!({"key": "value"}))
            );
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

    mod js_plaintext_to_plaintext_with_type {
        use super::*;

        #[test]
        fn test_string_to_utf8str() {
            let js_string = JsPlaintext::String("hello".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Utf8Str).unwrap();
            assert_eq!(result, Plaintext::Utf8Str(Some("hello".to_string())));
        }

        #[test]
        fn test_string_to_int_fails() {
            let js_string = JsPlaintext::String("123".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Unsupported conversion"));
        }

        #[test]
        fn test_number_to_float() {
            let js_number = JsPlaintext::Number(3.14);
            let result = js_number.to_plaintext_with_type(ColumnType::Float).unwrap();
            assert_eq!(result, Plaintext::Float(Some(3.14)));
        }

        #[test]
        fn test_number_to_decimal() {
            let js_number = JsPlaintext::Number(3.14);
            let result = js_number.to_plaintext_with_type(ColumnType::Decimal).unwrap();
            let expected_decimal = Decimal::try_from(3.14).unwrap();
            assert_eq!(result, Plaintext::Decimal(Some(expected_decimal)));
        }

        #[test]
        fn test_number_to_bigint_truncates() {
            let js_number = JsPlaintext::Number(42.7);
            let result = js_number.to_plaintext_with_type(ColumnType::BigInt).unwrap();
            assert_eq!(result, Plaintext::BigInt(Some(42)));
        }

        #[test]
        fn test_number_to_int_truncates() {
            let js_number = JsPlaintext::Number(42.7);
            let result = js_number.to_plaintext_with_type(ColumnType::Int).unwrap();
            assert_eq!(result, Plaintext::Int(Some(42)));
        }

        #[test]
        fn test_number_to_smallint_truncates() {
            let js_number = JsPlaintext::Number(42.7);
            let result = js_number.to_plaintext_with_type(ColumnType::SmallInt).unwrap();
            assert_eq!(result, Plaintext::SmallInt(Some(42)));
        }

        #[test]
        fn test_number_to_biguint() {
            let js_number = JsPlaintext::Number(42.0);
            let result = js_number.to_plaintext_with_type(ColumnType::BigUInt).unwrap();
            assert_eq!(result, Plaintext::BigUInt(Some(42)));
        }

        #[test]
        fn test_negative_number_to_biguint_fails() {
            let js_number = JsPlaintext::Number(-42.0);
            let result = js_number.to_plaintext_with_type(ColumnType::BigUInt);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("negative"));
        }

        #[test]
        fn test_boolean_to_boolean() {
            let js_bool = JsPlaintext::Boolean(true);
            let result = js_bool.to_plaintext_with_type(ColumnType::Boolean).unwrap();
            assert_eq!(result, Plaintext::Boolean(Some(true)));
        }

        #[test]
        fn test_boolean_to_string_fails() {
            let js_bool = JsPlaintext::Boolean(true);
            let result = js_bool.to_plaintext_with_type(ColumnType::Utf8Str);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Unsupported conversion"));
        }

        #[test]
        fn test_jsonb_to_jsonb() {
            let json_value = serde_json::json!({"key": "value"});
            let js_jsonb = JsPlaintext::JsonB(json_value.clone());
            let result = js_jsonb.to_plaintext_with_type(ColumnType::JsonB).unwrap();
            assert_eq!(result, Plaintext::JsonB(Some(json_value)));
        }

        #[test]
        fn test_jsonb_to_string_fails() {
            let json_value = serde_json::json!({"key": "value"});
            let js_jsonb = JsPlaintext::JsonB(json_value);
            let result = js_jsonb.to_plaintext_with_type(ColumnType::Utf8Str);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Unsupported conversion"));
        }

        #[test]
        fn test_number_to_boolean_fails() {
            let js_number = JsPlaintext::Number(1.0);
            let result = js_number.to_plaintext_with_type(ColumnType::Boolean);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Unsupported conversion"));
        }
    }
}
