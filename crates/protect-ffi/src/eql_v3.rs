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

use cipherstash_client::eql::{EqlCiphertext, EqlOutput, EqlQueryPayload};
use cipherstash_client::schema::{column::ColumnType, column::IndexType, ColumnConfig};
use cipherstash_client::zerokms::{self, EncryptedRecord, WithContext};
use eql_bindings::from_v2::{from_v2, from_v2_query, is_v3_payload, TargetDomain};
use eql_bindings::v3::jsonb::SteVecDocument;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

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
    //
    // The non-text arms rely on cipherstash-config rejecting `match` on
    // non-text casts upstream (into_column_config): were a non-text column
    // ever configured with `match` + `ore`, the `_ord_ore` arm below would
    // silently drop bf. Only the all-terms-dropped case (no fitting domain
    // at all) reaches the fail-closed error at the bottom.
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

/// A stored payload in whichever wire format the client is configured for.
///
/// `#[serde(untagged)]` makes the `V2` variant serialize exactly as the bare
/// [`EqlCiphertext`] did before dual-format support (no `Value` round-trip,
/// so v2 output is byte-identical), while `V3` carries the already-converted
/// JSON value. The v2 payload is boxed because it is substantially larger
/// than a `Value` (clippy's `large_enum_variant`).
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum EncryptedOutput {
    V2(Box<EqlCiphertext>),
    V3(serde_json::Value),
}

/// Wrap a Store-mode ciphertext in the client's configured wire format:
/// v2 passes through untouched; v3 converts via [`eql_bindings::from_v2`]
/// against the domain selected from the column configuration.
pub(crate) fn storage_output(
    ciphertext: EqlCiphertext,
    eql_version: u8,
    column_config: &ColumnConfig,
) -> Result<EncryptedOutput, Error> {
    if eql_version != EQL_VERSION_V3 {
        return Ok(EncryptedOutput::V2(Box::new(ciphertext)));
    }
    let target = v3_target_for_column(column_config)?;
    let v2_value = serde_json::to_value(&ciphertext)?;
    Ok(EncryptedOutput::V3(from_v2(&v2_value, target)?))
}

/// A query payload in whichever wire format the client is configured for.
/// Same untagged pass-through (and boxing) design as [`EncryptedOutput`].
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum QueryOutput {
    V2(Box<EqlOutput>),
    V3(serde_json::Value),
}

/// Wrap an encrypt-query result in the client's configured wire format.
///
/// Under v3, only the JSONB containment path converts: Store-mode containment
/// output (the `sv` document) becomes the `eql_v3.jsonb_query` needle via
/// [`from_v2_query`]. No v3 wire shape exists for scalar query terms or
/// selector payloads yet, so those fail closed with a typed error.
pub(crate) fn query_output(output: EqlOutput, eql_version: u8) -> Result<QueryOutput, Error> {
    if eql_version != EQL_VERSION_V3 {
        return Ok(QueryOutput::V2(Box::new(output)));
    }
    match output {
        // JSONB containment: Store mode always yields the sv document (that
        // is the only plaintext shape to_query_plaintext maps to StoreMode);
        // the needle strips the envelope and per-entry ciphertexts, exactly
        // like the SQL cast eql_v3.to_ste_vec_query.
        EqlOutput::Store(ciphertext @ EqlCiphertext::SteVec(_)) => {
            let v2_value = serde_json::to_value(&ciphertext)?;
            Ok(QueryOutput::V3(from_v2_query(
                &v2_value,
                TargetDomain::Json,
            )?))
        }
        EqlOutput::Store(EqlCiphertext::Encrypted(_)) => Err(Error::InvariantViolation(
            "store-mode query encryption produced a scalar payload".to_string(),
        )),
        // No v3 wire shape exists for these yet (pending the mapper
        // redesign) — fail closed with an actionable error.
        EqlOutput::Query(EqlQueryPayload::Encrypted(_)) => Err(Error::V3ScalarQueryUnsupported),
        EqlOutput::Query(EqlQueryPayload::SteVec(_)) => Err(Error::V3SelectorQueryUnsupported),
    }
}

/// Decode a stored ciphertext value in EITHER wire format into the record +
/// lock context pair zerokms decrypts.
///
/// Tries the v2 [`EqlCiphertext`] parse first (the historical shape), then
/// falls back to the v3 envelope. Decrypt is deliberately version-agnostic —
/// it must keep working across data migrations regardless of the client's
/// `eqlVersion` setting.
pub(crate) fn encrypted_record_from_value(
    value: serde_json::Value,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext<'static>, Error> {
    match EqlCiphertext::deserialize(&value) {
        Ok(ciphertext) => crate::encrypted_record_from_mp_base85(ciphertext, encryption_context),
        Err(v2_error) => {
            if is_v3_payload(&value) {
                Ok(WithContext {
                    record: v3_root_record(&value)?,
                    context: Cow::Owned(encryption_context),
                })
            } else {
                // Not v2, not v3 — report the v2 parse failure (the shape
                // the overwhelming majority of stored data still has).
                Err(Error::Parse(v2_error))
            }
        }
    }
}

/// Extract the record ciphertext from a v3 stored payload.
///
/// Scalars keep the mp_base85 record at the top-level `c`; SteVec documents
/// carry it on the FIRST `sv` entry (`sv[0].c`, the root-selector entry —
/// same invariant as v2, see `encrypted_record_from_mp_base85`).
///
/// The scalar arm reads `c` directly instead of parsing one of the ~40
/// generated domain structs: decrypt receives a bare ciphertext with no
/// column configuration, so the specific domain cannot be known here, and
/// the only field decryption needs is `c` (already shape-checked by
/// [`is_v3_payload`]). The structured SteVec arm goes through the typed
/// [`SteVecDocument`] so entry structure is validated before we trust
/// `sv[0]`.
fn v3_root_record(value: &serde_json::Value) -> Result<EncryptedRecord, Error> {
    if let Some(c) = value.get("c").and_then(serde_json::Value::as_str) {
        return EncryptedRecord::from_mp_base85(c).map_err(Error::from);
    }
    let document = SteVecDocument::deserialize(value).map_err(Error::Parse)?;
    let root = document.sv.first().ok_or_else(|| {
        Error::InvariantViolation("Missing root entry in v3 SteVec payload".to_string())
    })?;
    EncryptedRecord::from_mp_base85(&root.c.0).map_err(Error::from)
}

/// True when `value` is a stored EQL payload in either wire format.
///
/// v2 is the strict round-trip through [`EqlCiphertext`]; v3 is the lenient
/// envelope probe [`is_v3_payload`] (`{v: 3, i, c|sv}`). Query payloads —
/// including the v3 containment needle `{sv: […]}` — are not stored payloads
/// and return false.
pub(crate) fn is_encrypted_value(value: &serde_json::Value) -> bool {
    EqlCiphertext::deserialize(value).is_ok() || is_v3_payload(value)
}

/// Resolve the column's v3 domain name against the eql-bindings inventory.
///
/// [`target_domain_for_column`] only ever emits inventory names (pinned by a
/// unit test), so a parse failure here is a protect-ffi bug, not user error.
fn v3_target_for_column(column_config: &ColumnConfig) -> Result<TargetDomain, Error> {
    let domain = target_domain_for_column(column_config)?;
    TargetDomain::parse(&domain).map_err(|e| {
        Error::InvariantViolation(format!(
            "selected v3 domain {domain:?} is not in the eql-bindings inventory: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared payload builders for the conversion tests. These mirror the
    /// real wire shapes cipherstash-client emits (dummy key material, valid
    /// structure) — no mocking of the conversion path itself.
    mod support {
        use cipherstash_client::eql::{
            EncryptedPayload, EqlCiphertext, Identifier as EqlIdentifier, SteVecEntry,
            SteVecEntryTerm, SteVecPayload, EQL_SCHEMA_VERSION,
        };
        use cipherstash_client::schema::column::{ColumnMode, ColumnType, Index};
        use cipherstash_client::schema::ColumnConfig;
        use cipherstash_client::zerokms::EncryptedRecord;

        pub(super) fn dummy_encrypted_record() -> EncryptedRecord {
            EncryptedRecord {
                iv: Default::default(),
                ciphertext: vec![1; 16],
                tag: vec![2; 16],
                descriptor: "users/email".to_string(),
                keyset_id: None,
                decryption_policy: None,
            }
        }

        pub(super) fn scalar_payload(
            hm: Option<&str>,
            bf: Option<Vec<u16>>,
            ob: Option<Vec<&str>>,
        ) -> EqlCiphertext {
            EqlCiphertext::Encrypted(EncryptedPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: dummy_encrypted_record(),
                hmac_256: hm.map(String::from),
                bloom_filter: bf,
                ore_block_u64_8_256: ob
                    .map(|blocks| blocks.into_iter().map(String::from).collect()),
            })
        }

        pub(super) fn ste_vec_payload() -> EqlCiphertext {
            EqlCiphertext::SteVec(SteVecPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "profile"),
                ste_vec: vec![
                    SteVecEntry {
                        selector: "root".into(),
                        ciphertext: dummy_encrypted_record(),
                        is_array: None,
                        term: SteVecEntryTerm::Hmac {
                            hmac_256: "feedface".into(),
                        },
                    },
                    SteVecEntry {
                        selector: "leaf".into(),
                        ciphertext: dummy_encrypted_record(),
                        is_array: Some(true),
                        term: SteVecEntryTerm::OreCllw {
                            ore_cllw_8: "deadbeef".into(),
                        },
                    },
                ],
            })
        }

        pub(super) fn column(cast_type: ColumnType, indexes: Vec<Index>) -> ColumnConfig {
            ColumnConfig {
                name: "test_column".to_string(),
                cast_type,
                indexes,
                in_place: false,
                mode: ColumnMode::Encrypted,
            }
        }
    }

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

    mod storage_output {
        use super::support::{column, scalar_payload, ste_vec_payload};
        use super::*;
        use cipherstash_client::schema::column::{Index, IndexType, Tokenizer};

        fn text_search_column() -> ColumnConfig {
            column(
                ColumnType::Text,
                vec![
                    Index::new(IndexType::Unique {
                        token_filters: vec![],
                    }),
                    Index::new(IndexType::Ore),
                    Index::new(IndexType::Match {
                        tokenizer: Tokenizer::Standard,
                        token_filters: vec![],
                        k: 6,
                        m: 2048,
                        include_original: false,
                    }),
                ],
            )
        }

        #[test]
        fn v2_output_serializes_identically_to_the_bare_ciphertext() {
            let ciphertext = scalar_payload(Some("aa"), Some(vec![1, 2]), Some(vec!["bb"]));
            let expected = serde_json::to_string(&ciphertext).unwrap();

            let output = storage_output(
                scalar_payload(Some("aa"), Some(vec![1, 2]), Some(vec!["bb"])),
                2,
                &text_search_column(),
            )
            .unwrap();

            assert_eq!(serde_json::to_string(&output).unwrap(), expected);
        }

        #[test]
        fn v3_scalar_output_has_v3_envelope_and_required_terms() {
            let output = storage_output(
                scalar_payload(Some("aa"), Some(vec![1, 2]), Some(vec!["bb"])),
                3,
                &text_search_column(),
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["v"], 3);
            assert!(value.get("k").is_none(), "v3 envelope carries no k");
            assert_eq!(value["i"]["t"], "users");
            assert_eq!(value["i"]["c"], "email");
            assert!(value["c"].is_string(), "ciphertext is copied verbatim");
            assert_eq!(value["hm"], "aa");
            assert_eq!(value["ob"], serde_json::json!(["bb"]));
            assert_eq!(value["bf"], serde_json::json!([1, 2]));
        }

        #[test]
        fn v3_output_drops_terms_the_target_domain_does_not_carry() {
            // unique + ore on int maps to int4_ord_ore, which carries only
            // ob — hm is dropped (equality stays available via ORE).
            let cfg = column(
                ColumnType::Int,
                vec![
                    Index::new(IndexType::Unique {
                        token_filters: vec![],
                    }),
                    Index::new(IndexType::Ore),
                ],
            );
            let output =
                storage_output(scalar_payload(Some("aa"), None, Some(vec!["bb"])), 3, &cfg)
                    .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["ob"], serde_json::json!(["bb"]));
            assert!(value.get("hm").is_none(), "hm dropped for int4_ord_ore");
        }

        #[test]
        fn v3_bloom_filter_upper_half_wraps_to_signed() {
            // v2 emits unsigned bit positions; the v3 smallint[] encoding
            // reinterprets the upper half (32768..=65535) as negative i16.
            let output = storage_output(
                scalar_payload(Some("aa"), Some(vec![7, 40000]), Some(vec!["bb"])),
                3,
                &text_search_column(),
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["bf"], serde_json::json!([7, 40000u16 as i16]));
        }

        #[test]
        fn v3_ste_vec_output_is_a_ste_vec_document_with_order_preserved() {
            let cfg = column(
                ColumnType::Json,
                vec![Index::new(IndexType::SteVec {
                    prefix: "users/profile".to_string(),
                    term_filters: vec![],
                    array_index_mode: Default::default(),
                    mode: Default::default(),
                })],
            );
            let output = storage_output(ste_vec_payload(), 3, &cfg).unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["v"], 3);
            assert!(value.get("k").is_none(), "v3 envelope carries no k");
            let sv = value["sv"].as_array().unwrap();
            assert_eq!(sv.len(), 2);
            // sv[0] is the decryption root — order must survive conversion.
            assert_eq!(sv[0]["s"], "root");
            assert_eq!(sv[0]["hm"], "feedface");
            assert!(sv[0]["c"].is_string());
            assert_eq!(sv[1]["s"], "leaf");
            assert_eq!(sv[1]["oc"], "deadbeef");
            assert_eq!(sv[1]["a"], true);
        }

        #[test]
        fn v3_conversion_fails_closed_when_a_required_term_is_missing() {
            // text_search requires hm + ob + bf; a payload missing bf must
            // not silently degrade.
            let result = storage_output(
                scalar_payload(Some("aa"), None, Some(vec!["bb"])),
                3,
                &text_search_column(),
            );

            let err = result.unwrap_err().to_string();
            assert!(err.contains("bf"), "names the missing term: {err}");
            // Stable prefix: the TS side maps it to EQL_V3_CONVERSION_FAILED.
            assert!(
                err.starts_with("EQL v3 conversion failed"),
                "carries the conversion-failure prefix: {err}"
            );
        }
    }

    mod query_output {
        use super::support::ste_vec_payload;
        use super::*;
        use cipherstash_client::eql::{
            EncryptedQueryPayload, EqlOutput, EqlQueryPayload, Identifier as EqlIdentifier,
            RootQueryTerm, SteVecQueryPayload, SteVecQueryTerm, EQL_SCHEMA_VERSION,
        };

        fn scalar_query() -> EqlOutput {
            EqlOutput::Query(EqlQueryPayload::Encrypted(EncryptedQueryPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "email"),
                term: RootQueryTerm::Hmac {
                    hmac_256: "aa".into(),
                },
            }))
        }

        fn selector_query() -> EqlOutput {
            EqlOutput::Query(EqlQueryPayload::SteVec(SteVecQueryPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "profile"),
                term: SteVecQueryTerm::Selector {
                    selector: "deadbeef".into(),
                },
            }))
        }

        #[test]
        fn v2_output_serializes_identically_to_the_bare_eql_output() {
            let expected = serde_json::to_string(&scalar_query()).unwrap();

            let output = query_output(scalar_query(), 2).unwrap();

            assert_eq!(serde_json::to_string(&output).unwrap(), expected);
        }

        #[test]
        fn v2_containment_output_passes_through() {
            let expected = serde_json::to_string(&EqlOutput::Store(ste_vec_payload())).unwrap();

            let output = query_output(EqlOutput::Store(ste_vec_payload()), 2).unwrap();

            assert_eq!(serde_json::to_string(&output).unwrap(), expected);
        }

        #[test]
        fn v3_containment_output_is_a_jsonb_query_needle() {
            let output = query_output(EqlOutput::Store(ste_vec_payload()), 3).unwrap();

            let value = serde_json::to_value(&output).unwrap();
            // The eql_v3.jsonb_query needle: {sv: [{s, hm|oc}]} — no
            // envelope, no per-entry ciphertext or array marker.
            assert!(value.get("v").is_none(), "needle carries no envelope");
            assert!(value.get("i").is_none(), "needle carries no identifier");
            assert!(value.get("k").is_none(), "needle carries no k");
            let sv = value["sv"].as_array().unwrap();
            assert_eq!(sv.len(), 2);
            assert_eq!(sv[0]["s"], "root");
            assert_eq!(sv[0]["hm"], "feedface");
            assert!(sv[0].get("c").is_none(), "c is stripped from entries");
            assert_eq!(sv[1]["s"], "leaf");
            assert_eq!(sv[1]["oc"], "deadbeef");
            assert!(sv[1].get("a").is_none(), "a is stripped from entries");
        }

        #[test]
        fn v3_scalar_query_returns_a_typed_error() {
            let err = query_output(scalar_query(), 3).unwrap_err();

            assert!(matches!(err, Error::V3ScalarQueryUnsupported));
            assert_eq!(
                err.to_string(),
                "EQL v3 scalar query encryption is not yet supported — \
                 encrypt_query requires eqlVersion 2 for scalar indexes"
            );
        }

        #[test]
        fn v3_selector_query_returns_a_typed_error() {
            let err = query_output(selector_query(), 3).unwrap_err();

            assert!(matches!(err, Error::V3SelectorQueryUnsupported));
            assert!(
                err.to_string().contains("eqlVersion 2"),
                "hints at eqlVersion 2: {err}"
            );
        }
    }

    mod dual_format_decrypt {
        use super::support::{column, scalar_payload, ste_vec_payload};
        use super::*;
        use cipherstash_client::schema::column::{Index, IndexType};
        use serde_json::json;

        fn v2_scalar_value() -> serde_json::Value {
            serde_json::to_value(scalar_payload(Some("aa"), None, None)).unwrap()
        }

        fn v2_ste_vec_value() -> serde_json::Value {
            serde_json::to_value(ste_vec_payload()).unwrap()
        }

        fn v3_scalar_value() -> serde_json::Value {
            let cfg = column(
                ColumnType::Text,
                vec![Index::new(IndexType::Unique {
                    token_filters: vec![],
                })],
            );
            let output = storage_output(scalar_payload(Some("aa"), None, None), 3, &cfg).unwrap();
            serde_json::to_value(&output).unwrap()
        }

        fn v3_ste_vec_value() -> serde_json::Value {
            let cfg = column(
                ColumnType::Json,
                vec![Index::new(IndexType::SteVec {
                    prefix: "users/profile".to_string(),
                    term_filters: vec![],
                    array_index_mode: Default::default(),
                    mode: Default::default(),
                })],
            );
            let output = storage_output(ste_vec_payload(), 3, &cfg).unwrap();
            serde_json::to_value(&output).unwrap()
        }

        mod encrypted_record_from_value {
            use super::*;

            #[test]
            fn decodes_a_v2_scalar_payload() {
                let record = encrypted_record_from_value(v2_scalar_value(), vec![]).unwrap();
                assert_eq!(record.record.descriptor, "users/email");
            }

            #[test]
            fn decodes_a_v2_ste_vec_payload_from_the_root_entry() {
                let record = encrypted_record_from_value(v2_ste_vec_value(), vec![]).unwrap();
                assert_eq!(record.record.descriptor, "users/email");
            }

            #[test]
            fn decodes_a_v3_scalar_payload() {
                let record = encrypted_record_from_value(v3_scalar_value(), vec![]).unwrap();
                assert_eq!(record.record.descriptor, "users/email");
            }

            #[test]
            fn decodes_a_v3_ste_vec_document_from_sv_0() {
                let record = encrypted_record_from_value(v3_ste_vec_value(), vec![]).unwrap();
                assert_eq!(record.record.descriptor, "users/email");
            }

            #[test]
            fn preserves_the_lock_context() {
                let context = vec![zerokms::Context::IdentityClaim("sub".to_string())];
                let record =
                    encrypted_record_from_value(v3_scalar_value(), context.clone()).unwrap();
                assert_eq!(record.context.len(), 1);
            }

            #[test]
            fn rejects_plain_json() {
                let err = encrypted_record_from_value(json!({"random": "data"}), vec![]);
                assert!(err.is_err());
            }

            #[test]
            fn rejects_a_v3_document_with_an_empty_sv() {
                let value = json!({
                    "v": 3,
                    "i": {"t": "users", "c": "profile"},
                    "sv": []
                });
                let err = encrypted_record_from_value(value, vec![]).unwrap_err();
                assert!(
                    err.to_string().contains("root"),
                    "mentions the missing root entry: {err}"
                );
            }
        }

        mod is_encrypted_value {
            use super::*;

            #[test]
            fn accepts_both_wire_formats() {
                for value in [
                    v2_scalar_value(),
                    v2_ste_vec_value(),
                    v3_scalar_value(),
                    v3_ste_vec_value(),
                ] {
                    assert!(is_encrypted_value(&value), "should accept: {value}");
                }
            }

            #[test]
            fn rejects_non_payload_values() {
                for value in [
                    json!({"random": "data"}),
                    json!("plaintext"),
                    json!(42),
                    json!(null),
                    // v2 envelope without the k discriminator
                    json!({"v": 2, "i": {"t": "users", "c": "email"}}),
                    // a v3 containment needle is a QUERY payload, not storage
                    json!({"sv": [{"s": "aa", "hm": "bb"}]}),
                ] {
                    assert!(!is_encrypted_value(&value), "should reject: {value}");
                }
            }
        }
    }
}
