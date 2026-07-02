//! EQL v3 dual-format support.
//!
//! protect-ffi historically speaks the EQL v2.3 wire format (`{v: 2, k, i, c,
//! …}`). The `eql_v3` PostgreSQL schema replaces the single
//! `eql_v2_encrypted` column type with per-capability domains
//! (`eql_v3.text_eq`, `eql_v3.int4_ord_ore`, `eql_v3.json`, …) and a new
//! envelope (`{v: 3, i, c, <terms>}` — no `k` discriminator).
//!
//! Payloads are converted, not re-encrypted: cipherstash-client still emits
//! v2, and [`eql_bindings::from_v2`] rewrites the wire shape for the target
//! domain selected from the column configuration. Decryption accepts BOTH
//! formats regardless of the client's `eqlVersion` so data can be migrated
//! incrementally.

use cipherstash_client::schema::{column::ColumnType, column::IndexType, ColumnConfig};

use crate::Error;

/// The EQL wire version emitted when `eqlVersion` is omitted.
pub(crate) const DEFAULT_EQL_VERSION: u8 = 2;

/// The v3 EQL wire version.
pub(crate) const EQL_VERSION_V3: u8 = 3;

/// Validate the client-supplied `eqlVersion` option: only `2` and `3` are
/// EQL wire versions this crate can emit. `None` defaults to v2 for
/// backwards compatibility.
pub(crate) fn validate_eql_version(version: Option<u8>) -> Result<u8, Error> {
    match version {
        None => Ok(DEFAULT_EQL_VERSION),
        Some(v @ (DEFAULT_EQL_VERSION | EQL_VERSION_V3)) => Ok(v),
        Some(other) => Err(Error::InvalidEqlVersion(other)),
    }
}

/// The v2 index terms a column's configuration will produce on a stored
/// payload: `hm` from `unique`, `ob` from `ore`, `op` from `ope`, `bf` from
/// `match`, and the `sv` entry vector from `ste_vec`.
#[derive(Debug, Clone, Copy, Default)]
struct ConfiguredTerms {
    hm: bool,
    ob: bool,
    op: bool,
    bf: bool,
    sv: bool,
}

impl ConfiguredTerms {
    fn from_indexes(column_config: &ColumnConfig) -> Self {
        let mut terms = Self::default();
        for index in &column_config.indexes {
            match index.index_type {
                IndexType::Unique { .. } => terms.hm = true,
                IndexType::Ore => terms.ob = true,
                IndexType::Ope => terms.op = true,
                IndexType::Match { .. } => terms.bf = true,
                IndexType::SteVec { .. } => terms.sv = true,
            }
        }
        terms
    }

    fn any(&self) -> bool {
        self.hm || self.ob || self.op || self.bf || self.sv
    }
}

/// The v3 domain family for a `cast_as` type. `None` for [`ColumnType::BigUInt`],
/// which no `cast_as` value maps to (fail closed if it ever appears).
fn v3_family(cast_type: ColumnType) -> Option<&'static str> {
    match cast_type {
        ColumnType::Text => Some("text"),
        ColumnType::SmallInt => Some("int2"),
        ColumnType::Int => Some("int4"),
        ColumnType::BigInt => Some("int8"),
        ColumnType::Float => Some("float8"),
        ColumnType::Decimal => Some("numeric"),
        ColumnType::Date => Some("date"),
        ColumnType::Timestamp => Some("timestamp"),
        ColumnType::Boolean => Some("bool"),
        ColumnType::Json => Some("json"),
        ColumnType::BigUInt => None,
    }
}

fn no_v3_domain(column: &str, reason: impl Into<String>, hint: impl Into<String>) -> Error {
    Error::NoV3Domain {
        column: column.to_string(),
        reason: reason.into(),
        hint: hint.into(),
    }
}

/// Select the (unqualified) `eql_v3` domain for a column.
///
/// Every v2 index term is optional on the wire, so eql-bindings requires the
/// caller to name the target domain — this derives it from the column
/// configuration, choosing the domain that preserves the MOST configured
/// terms. Candidates are tried richest-first (`search` > `ord_ore` >
/// `ord_ope` > `match` > `eq` > storage-only), so ties break toward the
/// richer operator set:
///
/// - non-text `_ord_ore`/`_ord_ope` require only `ob`/`op` — a `unique` +
///   `ore` column drops `hm`, but equality stays available through the ORE
///   operators (`=`, `<>`);
/// - text ordering domains require `hm` alongside `ob`/`op`, so ordered text
///   without a `unique` index cannot be represented and errors;
/// - a column whose configured terms would ALL be dropped (bool with any
///   index, ordered-only text) errors rather than silently degrading to
///   storage-only.
pub(crate) fn target_domain_for_column(column_config: &ColumnConfig) -> Result<String, Error> {
    let column = column_config.name.as_str();
    let terms = ConfiguredTerms::from_indexes(column_config);
    let family = v3_family(column_config.cast_type).ok_or_else(|| {
        no_v3_domain(
            column,
            format!(
                "cast type {} has no EQL v3 domain family",
                column_config.cast_type
            ),
            "Use eqlVersion 2 for this column.",
        )
    })?;

    if family == "json" {
        return if terms.sv {
            Ok("json".to_string())
        } else {
            Err(no_v3_domain(
                column,
                "EQL v3 has no scalar jsonb domain for an index-less JSON column",
                "Add a 'ste_vec' index or use eqlVersion 2.",
            ))
        };
    }

    if family == "bool" {
        return if terms.any() {
            Err(no_v3_domain(
                column,
                "eql_v3.bool is storage-only but indexes are configured",
                "Remove the indexes or use eqlVersion 2.",
            ))
        } else {
            Ok("bool".to_string())
        };
    }

    // Scalar families, richest capability first. Text ordering domains carry
    // hm + ob/op; the non-text ordering domains carry only ob/op.
    let is_text = family == "text";
    if is_text && terms.hm && terms.ob && terms.bf {
        return Ok(format!("{family}_search"));
    }
    if terms.ob && (!is_text || terms.hm) {
        return Ok(format!("{family}_ord_ore"));
    }
    if terms.op && (!is_text || terms.hm) {
        return Ok(format!("{family}_ord_ope"));
    }
    if is_text && terms.bf {
        return Ok(format!("{family}_match"));
    }
    if terms.hm {
        return Ok(format!("{family}_eq"));
    }
    if terms.any() {
        // Configured terms exist but none of the family's domains can carry
        // them (ore/ope-only text, match on a non-text cast, …). Falling back
        // to storage-only would silently drop every configured capability.
        return Err(no_v3_domain(
            column,
            format!("no eql_v3.{family} domain can carry the configured index terms"),
            "Ordered text requires a 'unique' index alongside 'ore'/'ope' \
             (v3 text ordering domains carry hm + ob/op). Adjust the indexes \
             or use eqlVersion 2.",
        ));
    }
    Ok(family.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    mod validate_eql_version {
        use super::*;

        #[test]
        fn defaults_to_v2_when_absent() {
            assert_eq!(validate_eql_version(None).unwrap(), 2);
        }

        #[test]
        fn accepts_v2() {
            assert_eq!(validate_eql_version(Some(2)).unwrap(), 2);
        }

        #[test]
        fn accepts_v3() {
            assert_eq!(validate_eql_version(Some(3)).unwrap(), 3);
        }

        #[test]
        fn rejects_other_versions() {
            for v in [0u8, 1, 4, 255] {
                let err = validate_eql_version(Some(v)).unwrap_err();
                assert!(
                    err.to_string().contains("eqlVersion"),
                    "error should mention eqlVersion: {err}"
                );
            }
        }
    }

    mod target_domain_for_column {
        use super::*;
        use cipherstash_client::schema::column::{ColumnMode, Index, Tokenizer};
        use eql_bindings::from_v2::TargetDomain;

        fn column(cast_type: ColumnType, indexes: Vec<Index>) -> ColumnConfig {
            ColumnConfig {
                name: "test_column".to_string(),
                cast_type,
                indexes,
                in_place: false,
                mode: ColumnMode::Encrypted,
            }
        }

        fn unique() -> Index {
            Index::new(IndexType::Unique {
                token_filters: vec![],
            })
        }

        fn ore() -> Index {
            Index::new(IndexType::Ore)
        }

        fn ope() -> Index {
            Index::new(IndexType::Ope)
        }

        fn match_index() -> Index {
            Index::new(IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 6,
                m: 2048,
                include_original: false,
            })
        }

        fn ste_vec() -> Index {
            Index::new(IndexType::SteVec {
                prefix: "t/c".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            })
        }

        fn domain(cast_type: ColumnType, indexes: Vec<Index>) -> String {
            target_domain_for_column(&column(cast_type, indexes)).unwrap()
        }

        fn domain_err(cast_type: ColumnType, indexes: Vec<Index>) -> String {
            target_domain_for_column(&column(cast_type, indexes))
                .unwrap_err()
                .to_string()
        }

        #[test]
        fn text_without_indexes_is_storage_only() {
            assert_eq!(domain(ColumnType::Text, vec![]), "text");
        }

        #[test]
        fn text_unique_is_eq() {
            assert_eq!(domain(ColumnType::Text, vec![unique()]), "text_eq");
        }

        #[test]
        fn text_match_is_match() {
            assert_eq!(domain(ColumnType::Text, vec![match_index()]), "text_match");
        }

        #[test]
        fn text_unique_and_ore_is_ord_ore() {
            assert_eq!(
                domain(ColumnType::Text, vec![unique(), ore()]),
                "text_ord_ore"
            );
        }

        #[test]
        fn text_unique_and_ope_is_ord_ope() {
            assert_eq!(
                domain(ColumnType::Text, vec![unique(), ope()]),
                "text_ord_ope"
            );
        }

        #[test]
        fn text_unique_ore_match_is_search() {
            assert_eq!(
                domain(ColumnType::Text, vec![unique(), ore(), match_index()]),
                "text_search"
            );
        }

        #[test]
        fn text_unique_and_match_prefers_match_over_eq() {
            // Precedence for ties: search > ord_ore > ord_ope > match > eq.
            assert_eq!(
                domain(ColumnType::Text, vec![unique(), match_index()]),
                "text_match"
            );
        }

        #[test]
        fn text_match_and_ore_without_unique_is_match() {
            // text ordering domains need hm; bf is still representable.
            assert_eq!(
                domain(ColumnType::Text, vec![match_index(), ore()]),
                "text_match"
            );
        }

        #[test]
        fn text_ore_without_unique_is_an_error() {
            // eql_v3.text_ord_ore requires hm + ob; an ore-only text column
            // yields no hm, and falling back to storage-only would silently
            // drop the configured ordering capability.
            let err = domain_err(ColumnType::Text, vec![ore()]);
            assert!(err.contains("test_column"), "names the column: {err}");
            assert!(err.contains("unique"), "hints at adding unique: {err}");
        }

        #[test]
        fn text_ope_without_unique_is_an_error() {
            let err = domain_err(ColumnType::Text, vec![ope()]);
            assert!(err.contains("unique"), "hints at adding unique: {err}");
        }

        #[test]
        fn int_without_indexes_is_storage_only() {
            assert_eq!(domain(ColumnType::Int, vec![]), "int4");
        }

        #[test]
        fn int_unique_is_eq() {
            assert_eq!(domain(ColumnType::Int, vec![unique()]), "int4_eq");
        }

        #[test]
        fn int_ore_is_ord_ore() {
            assert_eq!(domain(ColumnType::Int, vec![ore()]), "int4_ord_ore");
        }

        #[test]
        fn int_ope_is_ord_ope() {
            assert_eq!(domain(ColumnType::Int, vec![ope()]), "int4_ord_ope");
        }

        #[test]
        fn int_unique_and_ore_prefers_ord_ore_over_eq() {
            // int4_ord_ore requires only ob; hm is dropped but equality
            // remains available via the ORE operators (= <>).
            assert_eq!(
                domain(ColumnType::Int, vec![unique(), ore()]),
                "int4_ord_ore"
            );
        }

        #[test]
        fn int_unique_and_ope_prefers_ord_ope_over_eq() {
            assert_eq!(
                domain(ColumnType::Int, vec![unique(), ope()]),
                "int4_ord_ope"
            );
        }

        #[test]
        fn int_ore_and_ope_prefers_ord_ore() {
            assert_eq!(domain(ColumnType::Int, vec![ore(), ope()]), "int4_ord_ore");
        }

        #[test]
        fn small_int_maps_to_int2_family() {
            assert_eq!(domain(ColumnType::SmallInt, vec![ore()]), "int2_ord_ore");
        }

        #[test]
        fn big_int_maps_to_int8_family() {
            assert_eq!(domain(ColumnType::BigInt, vec![unique()]), "int8_eq");
        }

        #[test]
        fn float_maps_to_float8_family() {
            assert_eq!(domain(ColumnType::Float, vec![ore()]), "float8_ord_ore");
        }

        #[test]
        fn decimal_maps_to_numeric_family() {
            assert_eq!(domain(ColumnType::Decimal, vec![ore()]), "numeric_ord_ore");
        }

        #[test]
        fn date_maps_to_date_family() {
            assert_eq!(domain(ColumnType::Date, vec![ore()]), "date_ord_ore");
        }

        #[test]
        fn timestamp_maps_to_timestamp_family() {
            assert_eq!(
                domain(ColumnType::Timestamp, vec![unique()]),
                "timestamp_eq"
            );
        }

        #[test]
        fn boolean_without_indexes_is_storage_only() {
            assert_eq!(domain(ColumnType::Boolean, vec![]), "bool");
        }

        #[test]
        fn boolean_with_unique_is_an_error() {
            // eql_v3.bool is storage-only; any index term would be dropped.
            let err = domain_err(ColumnType::Boolean, vec![unique()]);
            assert!(err.contains("test_column"), "names the column: {err}");
            assert!(err.contains("storage-only"), "explains bool: {err}");
        }

        #[test]
        fn boolean_with_ore_is_an_error() {
            let err = domain_err(ColumnType::Boolean, vec![ore()]);
            assert!(err.contains("storage-only"), "explains bool: {err}");
        }

        #[test]
        fn json_with_ste_vec_is_json() {
            assert_eq!(domain(ColumnType::Json, vec![ste_vec()]), "json");
        }

        #[test]
        fn json_without_ste_vec_is_an_error() {
            // v2 stores index-less JSON as an opaque scalar (k: "ct"); v3
            // has no scalar jsonb domain to hold it.
            let err = domain_err(ColumnType::Json, vec![]);
            assert!(err.contains("ste_vec"), "hints at ste_vec: {err}");
        }

        #[test]
        fn match_on_non_text_is_an_error() {
            // The config layer rejects this before it reaches us; fail
            // closed anyway rather than silently dropping bf.
            let err = domain_err(ColumnType::Int, vec![match_index()]);
            assert!(err.contains("test_column"), "names the column: {err}");
        }

        #[test]
        fn every_selected_domain_resolves_in_the_v3_inventory() {
            // The names this function emits must always parse against the
            // catalog-generated inventory — a typo here would only surface
            // at encrypt time otherwise.
            let cases: Vec<(ColumnType, Vec<Index>)> = vec![
                (ColumnType::Text, vec![]),
                (ColumnType::Text, vec![unique()]),
                (ColumnType::Text, vec![match_index()]),
                (ColumnType::Text, vec![unique(), ore()]),
                (ColumnType::Text, vec![unique(), ope()]),
                (ColumnType::Text, vec![unique(), ore(), match_index()]),
                (ColumnType::SmallInt, vec![]),
                (ColumnType::SmallInt, vec![unique()]),
                (ColumnType::SmallInt, vec![ore()]),
                (ColumnType::SmallInt, vec![ope()]),
                (ColumnType::Int, vec![ore()]),
                (ColumnType::BigInt, vec![ore()]),
                (ColumnType::Float, vec![ore()]),
                (ColumnType::Decimal, vec![ore()]),
                (ColumnType::Date, vec![ore()]),
                (ColumnType::Timestamp, vec![ore()]),
                (ColumnType::Boolean, vec![]),
                (ColumnType::Json, vec![ste_vec()]),
            ];
            for (cast_type, indexes) in cases {
                let name = domain(cast_type, indexes);
                assert!(
                    TargetDomain::parse(&name).is_ok(),
                    "domain {name:?} must resolve in the eql-bindings inventory"
                );
            }
        }
    }
}
