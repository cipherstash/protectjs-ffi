use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use cipherstash_client::encryption::{Plaintext, TryFromPlaintext, TypeParseError};
use cipherstash_client::schema::ColumnType;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use vitaminc::protected::OpaqueDebug;

#[derive(Deserialize, Serialize, OpaqueDebug, PartialEq)]
#[serde(untagged)]
pub(crate) enum JsPlaintext {
    // `String` is first so that RFC 3339 strings (as produced by
    // `Date.prototype.toJSON()` on the JS side) deserialize as strings, not
    // as `Date`. `to_plaintext_with_type` parses them into `Plaintext::Date` /
    // `Plaintext::Timestamp` when the column's `cast_as` requires it.
    String(String),
    Number(f64),
    Boolean(bool),
    // Produced only on the decrypt path from `Plaintext::NaiveDate` /
    // `Plaintext::Timestamp`. Serializes as a plain RFC 3339 string via
    // chrono's default impl, so the JS side receives a string and can call
    // `new Date(...)` if needed.
    Date(DateTime<Utc>),
    JsonB(serde_json::Value),
}

impl From<JsPlaintext> for Plaintext {
    fn from(value: JsPlaintext) -> Self {
        match value {
            JsPlaintext::String(s) => Plaintext::Utf8Str(Some(s)),
            JsPlaintext::Number(n) => Plaintext::Float(Some(n)),
            JsPlaintext::Boolean(b) => Plaintext::Boolean(Some(b)),
            JsPlaintext::JsonB(j) => Plaintext::JsonB(Some(j)),
            JsPlaintext::Date(dt) => Plaintext::Timestamp(Some(dt)),
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
            Plaintext::NaiveDate(Some(nd)) => {
                // Promote date-only to midnight UTC so the JS-visible form is a
                // full timestamp.
                let dt =
                    Utc.from_utc_datetime(&nd.and_hms_opt(0, 0, 0).expect("00:00:00 is valid"));
                Ok(JsPlaintext::Date(dt))
            }
            Plaintext::Timestamp(Some(ts)) => Ok(JsPlaintext::Date(ts)),
            _ => Err(TypeParseError("Unsupported type".to_string())),
        }
    }
}

impl JsPlaintext {
    /// Convert JsPlaintext to Plaintext based on a target ColumnType.
    ///
    /// The storage type is driven by `cast_as`, not by the input variant.
    /// A JS Date (arriving as an RFC 3339 string via `Date.prototype.toJSON()`
    /// or as a `JsPlaintext::Date` produced by a prior decrypt) can be stored
    /// as a day-only `Date`, a full `Timestamp`, or an ISO 8601 string.
    pub fn to_plaintext_with_type(
        &self,
        column_type: ColumnType,
    ) -> Result<Plaintext, TypeParseError> {
        match (self, column_type) {
            // String conversions - Utf8Str, Date, and Timestamp (the latter two parse).
            (JsPlaintext::String(s), ColumnType::Utf8Str) => {
                Ok(Plaintext::Utf8Str(Some(s.clone())))
            }
            (JsPlaintext::String(s), ColumnType::Date) => parse_naive_date(s)
                .map(|d| Plaintext::NaiveDate(Some(d)))
                .map_err(|e| TypeParseError(format!("Cannot parse Date: {}", e))),
            (JsPlaintext::String(s), ColumnType::Timestamp) => parse_timestamp(s)
                .map(|t| Plaintext::Timestamp(Some(t)))
                .map_err(|e| TypeParseError(format!("Cannot parse Timestamp: {}", e))),

            // Number conversions - allow to numeric types with potential truncation/coercion
            (JsPlaintext::Number(n), ColumnType::Float) => Ok(Plaintext::Float(Some(*n))),
            (JsPlaintext::Number(n), ColumnType::Decimal) => Decimal::try_from(*n)
                .map(|d| Plaintext::Decimal(Some(d)))
                .map_err(|e| TypeParseError(format!("Cannot convert number to Decimal: {}", e))),
            (JsPlaintext::Number(n), ColumnType::BigInt) => Ok(Plaintext::BigInt(Some(*n as i64))),
            (JsPlaintext::Number(n), ColumnType::Int) => Ok(Plaintext::Int(Some(*n as i32))),
            (JsPlaintext::Number(n), ColumnType::SmallInt) => {
                Ok(Plaintext::SmallInt(Some(*n as i16)))
            }
            (JsPlaintext::Number(n), ColumnType::BigUInt) => {
                if *n < 0.0 {
                    Err(TypeParseError(
                        "Cannot convert negative number to BigUInt".to_string(),
                    ))
                } else {
                    Ok(Plaintext::BigUInt(Some(*n as u64)))
                }
            }

            // Boolean conversions - only allow to Boolean
            (JsPlaintext::Boolean(b), ColumnType::Boolean) => Ok(Plaintext::Boolean(Some(*b))),

            // JsonB conversions - only allow to JsonB
            (JsPlaintext::JsonB(j), ColumnType::JsonB) => Ok(Plaintext::JsonB(Some(j.clone()))),

            // Date conversions: the value is a full UTC timestamp; cast_as picks
            // the storage form.
            (JsPlaintext::Date(dt), ColumnType::Date) => {
                Ok(Plaintext::NaiveDate(Some(dt.date_naive())))
            }
            (JsPlaintext::Date(dt), ColumnType::Timestamp) => Ok(Plaintext::Timestamp(Some(*dt))),
            (JsPlaintext::Date(dt), ColumnType::Utf8Str) => {
                Ok(Plaintext::Utf8Str(Some(dt.to_rfc3339())))
            }

            // All other conversions are not allowed - provide helpful error message
            (js_type, col_type) => {
                let valid_targets = match js_type {
                    JsPlaintext::String(_) => {
                        "Utf8Str (string columns), Date, Timestamp (ISO 8601 strings)"
                    }
                    JsPlaintext::Number(_) => {
                        "Float, BigInt, Int, SmallInt, BigUInt, Decimal (numeric columns)"
                    }
                    JsPlaintext::Boolean(_) => "Boolean (boolean columns)",
                    JsPlaintext::JsonB(_) => "JsonB (json columns)",
                    JsPlaintext::Date(_) => {
                        "Date, Timestamp (date/timestamp columns), Utf8Str (ISO 8601 string)"
                    }
                };
                let type_name = js_plaintext_type_name(js_type);
                Err(TypeParseError(format!(
                    "Cannot convert {} to {:?}. {} values can only be used with: {}. \
                    Check your column's cast_as setting in the encrypt config.",
                    type_name, col_type, type_name, valid_targets
                )))
            }
        }
    }
}

/// Parse a string into a `NaiveDate`. Accepts full RFC 3339 timestamps (the
/// common case — JS `Date.prototype.toJSON()` always emits RFC 3339) and also
/// `YYYY-MM-DD` for callers who pass a bare date.
fn parse_naive_date(s: &str) -> Result<NaiveDate, String> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc).date_naive());
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|e| e.to_string())
}

/// Parse a string into a UTC `DateTime`. Accepts RFC 3339 (the format JS `Date`
/// objects produce via `toJSON()`).
fn parse_timestamp(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| e.to_string())
}

/// Helper function to get a readable type name for error messages
pub(crate) fn js_plaintext_type_name(js_plaintext: &JsPlaintext) -> &'static str {
    match js_plaintext {
        JsPlaintext::String(_) => "String",
        JsPlaintext::Number(_) => "Number",
        JsPlaintext::Boolean(_) => "Boolean",
        JsPlaintext::JsonB(_) => "JsonB",
        JsPlaintext::Date(_) => "Date",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_plaintext::JsPlaintext;

    fn sample_dt() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-03-14T12:34:56.789Z")
            .unwrap()
            .with_timezone(&Utc)
    }

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

        #[test]
        fn test_date_to_timestamp_plaintext() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let pt: Plaintext = js.into();
            assert_eq!(
                pt,
                Plaintext::Timestamp(Some(t)),
                "JsPlaintext::Date should map to Plaintext::Timestamp without column-type context"
            );
        }
    }

    mod plaintext_to_js_plaintext {
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
        fn test_naive_date_becomes_date_at_midnight_utc() {
            let d = NaiveDate::from_ymd_opt(2025, 3, 14).unwrap();
            let pt = Plaintext::NaiveDate(Some(d));
            let js: JsPlaintext = pt.try_into().unwrap();
            let expected = Utc.with_ymd_and_hms(2025, 3, 14, 0, 0, 0).unwrap();
            assert_eq!(
                js,
                JsPlaintext::Date(expected),
                "NaiveDate should promote to midnight UTC on the JS side"
            );
        }

        #[test]
        fn test_timestamp_becomes_date() {
            let t = sample_dt();
            let pt = Plaintext::Timestamp(Some(t));
            let js: JsPlaintext = pt.try_into().unwrap();
            assert_eq!(
                js,
                JsPlaintext::Date(t),
                "Plaintext::Timestamp should map to JsPlaintext::Date preserving the value"
            );
        }

        #[test]
        fn test_unsupported_type() {
            let result: Result<JsPlaintext, TypeParseError> = Plaintext::Int(Some(42)).try_into();
            assert!(
                result.is_err(),
                "Plaintext::Int has no JsPlaintext mapping and should fail"
            );
        }
    }

    mod js_plaintext_to_plaintext_with_type {
        use super::*;

        #[test]
        fn test_string_to_utf8str() {
            let js_string = JsPlaintext::String("hello".to_string());
            let result = js_string
                .to_plaintext_with_type(ColumnType::Utf8Str)
                .unwrap();
            assert_eq!(result, Plaintext::Utf8Str(Some("hello".to_string())));
        }

        #[test]
        fn test_string_to_int_fails() {
            let js_string = JsPlaintext::String("123".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_number_to_float() {
            let js_number = JsPlaintext::Number(3.78);
            let result = js_number.to_plaintext_with_type(ColumnType::Float).unwrap();
            assert_eq!(result, Plaintext::Float(Some(3.78)));
        }

        #[test]
        fn test_number_to_decimal() {
            let js_number = JsPlaintext::Number(3.78);
            let result = js_number
                .to_plaintext_with_type(ColumnType::Decimal)
                .unwrap();
            let expected_decimal = Decimal::try_from(3.78).unwrap();
            assert_eq!(result, Plaintext::Decimal(Some(expected_decimal)));
        }

        #[test]
        fn test_number_to_bigint_truncates() {
            let js_number = JsPlaintext::Number(42.7);
            let result = js_number
                .to_plaintext_with_type(ColumnType::BigInt)
                .unwrap();
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
            let result = js_number
                .to_plaintext_with_type(ColumnType::SmallInt)
                .unwrap();
            assert_eq!(result, Plaintext::SmallInt(Some(42)));
        }

        #[test]
        fn test_number_to_biguint() {
            let js_number = JsPlaintext::Number(42.0);
            let result = js_number
                .to_plaintext_with_type(ColumnType::BigUInt)
                .unwrap();
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
            assert!(result.unwrap_err().0.contains("Cannot convert"));
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
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_number_to_boolean_fails() {
            let js_number = JsPlaintext::Number(1.0);
            let result = js_number.to_plaintext_with_type(ColumnType::Boolean);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_iso_date_string_to_date() {
            let js_string = JsPlaintext::String("2025-03-14".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Date).unwrap();
            assert_eq!(
                result,
                Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2025, 3, 14).unwrap()))
            );
        }

        #[test]
        fn test_rfc3339_string_to_date_truncates_time() {
            let js_string = JsPlaintext::String("2025-03-14T12:34:56.789Z".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Date).unwrap();
            assert_eq!(
                result,
                Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2025, 3, 14).unwrap()))
            );
        }

        #[test]
        fn test_rfc3339_string_to_timestamp() {
            let js_string = JsPlaintext::String("2025-03-14T12:34:56.789Z".to_string());
            let result = js_string
                .to_plaintext_with_type(ColumnType::Timestamp)
                .unwrap();
            assert_eq!(result, Plaintext::Timestamp(Some(sample_dt())));
        }

        #[test]
        fn test_invalid_date_string_fails() {
            let js_string = JsPlaintext::String("not a date".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Date);
            let err = result.expect_err("unparseable input must fail");
            assert!(
                err.0.contains("Cannot parse Date"),
                "error should name the failing target type, got: {}",
                err.0
            );
            assert!(
                !err.0.contains("not a date"),
                "error must not echo the user's input (possible secret leak), got: {}",
                err.0
            );
        }

        #[test]
        fn test_invalid_timestamp_string_fails() {
            let js_string = JsPlaintext::String("2025-03-14".to_string()); // date-only, not rfc3339
            let result = js_string.to_plaintext_with_type(ColumnType::Timestamp);
            let err =
                result.expect_err("date-only string must fail as Timestamp (requires RFC 3339)");
            assert!(
                err.0.contains("Cannot parse Timestamp"),
                "error should name the failing target type, got: {}",
                err.0
            );
            assert!(
                !err.0.contains("2025-03-14"),
                "error must not echo the user's input (possible secret leak), got: {}",
                err.0
            );
        }

        #[test]
        fn test_date_value_to_timestamp_column() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let result = js.to_plaintext_with_type(ColumnType::Timestamp).unwrap();
            assert_eq!(result, Plaintext::Timestamp(Some(t)));
        }

        #[test]
        fn test_date_value_to_date_column_truncates() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let result = js.to_plaintext_with_type(ColumnType::Date).unwrap();
            assert_eq!(
                result,
                Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2025, 3, 14).unwrap()))
            );
        }

        #[test]
        fn test_date_value_to_string_column_serializes_rfc3339() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let result = js.to_plaintext_with_type(ColumnType::Utf8Str).unwrap();
            if let Plaintext::Utf8Str(Some(ref s)) = result {
                let parsed = DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
                assert_eq!(parsed, t);
            } else {
                panic!("Expected Plaintext::Utf8Str");
            }
        }

        #[test]
        fn test_date_value_to_bigint_fails() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let result = js.to_plaintext_with_type(ColumnType::BigInt);
            assert!(
                result.is_err(),
                "Date should not coerce into a numeric column"
            );
        }

        #[test]
        fn test_date_serializes_as_rfc3339_string() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let s = serde_json::to_string(&js).unwrap();
            assert_eq!(
                s, r#""2025-03-14T12:34:56.789Z""#,
                "Date must serialize as a plain RFC 3339 string so JS callers can build a Date from it"
            );
        }

        #[test]
        fn test_rfc3339_string_deserializes_as_string_not_date() {
            // `String` precedes `Date` in the untagged enum order, which is load-bearing:
            // user-supplied strings must never be silently reinterpreted as dates; date
            // parsing only happens in `to_plaintext_with_type` when the column demands it.
            let parsed: JsPlaintext =
                serde_json::from_str(r#""2025-03-14T12:34:56.789Z""#).unwrap();
            assert!(
                matches!(parsed, JsPlaintext::String(_)),
                "RFC 3339 strings must deserialize as JsPlaintext::String, not JsPlaintext::Date"
            );
        }

        #[test]
        fn test_type_coercion_error_shows_valid_alternatives() {
            // Test that error messages show what types are valid for each JS type
            let js_string = JsPlaintext::String("hello".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            // Should mention valid targets for String
            assert!(
                err_msg.contains("Utf8Str"),
                "Error should mention valid target Utf8Str: {}",
                err_msg
            );
            // Should mention cast_as setting
            assert!(
                err_msg.contains("cast_as"),
                "Error should mention cast_as setting: {}",
                err_msg
            );

            // Test Number type shows its valid targets
            let js_number = JsPlaintext::Number(42.0);
            let result = js_number.to_plaintext_with_type(ColumnType::Boolean);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            // Should mention valid targets for Number
            assert!(
                err_msg.contains("Float") || err_msg.contains("BigInt"),
                "Error should mention valid numeric targets: {}",
                err_msg
            );

            // Test Boolean shows its valid target
            let js_bool = JsPlaintext::Boolean(true);
            let result = js_bool.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            assert!(
                err_msg.contains("Boolean"),
                "Error should mention valid target Boolean: {}",
                err_msg
            );

            // Test JsonB shows its valid target
            let js_json = JsPlaintext::JsonB(serde_json::json!({"a": 1}));
            let result = js_json.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            assert!(
                err_msg.contains("JsonB"),
                "Error should mention valid target JsonB: {}",
                err_msg
            );
        }
    }
}
