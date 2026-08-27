// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::utils::{base64url_decode, jwt_payload_decode};

use error::Result;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::str::FromStr;
use strum::Display;
pub use {
    holder::SDJWTHolder, issuer::ClaimsForSelectiveDisclosureStrategy, issuer::SDJWTIssuer,
    verifier::SDJWTVerifier,
};

pub type KeyResolver = dyn Fn(&str, &Header) -> DecodingKey;

mod disclosure;
mod disclosure_preprocessing;
pub mod error;
pub mod holder;
pub mod issuer;
pub mod utils;
pub mod verifier;

pub const DEFAULT_SIGNING_ALG: &str = "ES256";
const SD_DIGESTS_KEY: &str = "_sd";
const DIGEST_ALG_KEY: &str = "_sd_alg";
pub const DEFAULT_DIGEST_ALG: &str = "sha-256";
const SD_LIST_PREFIX: &str = "...";
const _SD_JWT_TYP_HEADER: &str = "sd+jwt";
const KB_JWT_TYP_HEADER: &str = "kb+jwt";
const KB_DIGEST_KEY: &str = "sd_hash";
pub const COMBINED_SERIALIZATION_FORMAT_SEPARATOR: &str = "~";
const JWT_SEPARATOR: &str = ".";
const CNF_KEY: &str = "cnf";
const JWK_KEY: &str = "jwk";

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct SDJWTHasSDClaimException(String);

impl SDJWTHasSDClaimException {}

/// SDJWTSerializationFormat is used to determine how an SD-JWT is serialized to String
#[derive(Default, Clone, PartialEq, Debug, Display)]
pub enum SDJWTSerializationFormat {
    /// Flattened JWS JSON representation
    #[default]
    FlattenedJson,
    /// General JWS JSON representation
    GeneralJson,
    /// Base64-encoded representation
    Compact,
}

#[derive(Default)]
pub(crate) struct SDJWTCommon {
    typ: Option<String>,
    serialization_format: SDJWTSerializationFormat,
    unverified_input_key_binding_jwt: Option<String>,
    unverified_sd_jwt: Option<String>,
    unverified_input_sd_jwt_payload: Option<Map<String, Value>>,
    hash_to_decoded_disclosure: HashMap<String, Value>,
    hash_to_disclosure: HashMap<String, String>,
    input_disclosures: Vec<String>,
    ordered_disclosure_digests: Vec<String>,
    sign_alg: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SDJWTFlattenedJson {
    protected: String,
    payload: String,
    signature: String,
    pub header: SDJWTUnprotectedHeader,
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SDJWTGeneralJson {
    payload: String,
    pub signatures: Vec<SDJWTGeneralJsonSignature>,
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SDJWTGeneralJsonSignature {
    protected: String,
    signature: String,
    pub header: SDJWTUnprotectedHeader,
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SDJWTUnprotectedHeader {
    pub disclosures: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kb_jwt: Option<String>,
}

// Define the SDJWTCommon struct to hold common properties.
impl SDJWTCommon {
    fn verify_signature(&self, key: &DecodingKey) -> Result<()> {
        let sd_jwt = self
            .unverified_sd_jwt
            .as_ref()
            .ok_or(Error::InvalidState("Cannot reference jwt".to_string()))?;
        let alg_str = self.sign_alg.as_deref().ok_or_else(|| {
            Error::InvalidInput(
                "Issuer-signed JWT header is missing the `alg` parameter".to_string(),
            )
        })?;
        let algorithm =
            Algorithm::from_str(alg_str).map_err(|e| Error::DeserializationError(e.to_string()))?;
        let mut validation = Validation::new(algorithm);
        // RFC 9901 §4.1: `exp` is not mandated, so don't require it. `validate_exp`
        // stays true, so a present `exp` is still checked for expiry.
        validation.required_spec_claims.remove("exp");
        // `nbf` is optional too (not added to required_spec_claims), but when
        // present it must be honored; jsonwebtoken leaves `validate_nbf` off.
        validation.validate_nbf = true;
        // A present `aud` in the Issuer-signed JWT is the Issuer's audience, not one
        // the Holder validates here; jsonwebtoken rejects a present `aud` when no
        // expected audience is set, so disable that check for the signature step.
        validation.validate_aud = false;
        jsonwebtoken::decode::<Map<String, Value>>(sd_jwt, key, &validation).map_err(|e| {
            Error::DeserializationError(format!("Issuer signature verification failed: {}", e))
        })?;
        Ok(())
    }

    fn create_hash_mappings(&mut self) -> Result<()> {
        self.hash_to_decoded_disclosure = HashMap::new();
        self.hash_to_disclosure = HashMap::new();
        self.ordered_disclosure_digests = Vec::new();

        let mappings = disclosure_preprocessing::preprocess_disclosures(&self.input_disclosures)?;
        self.hash_to_decoded_disclosure = mappings.hash_to_decoded_disclosure;
        self.hash_to_disclosure = mappings.hash_to_disclosure;
        self.ordered_disclosure_digests = mappings.ordered_disclosure_digests;

        Ok(())
    }

    fn check_for_sd_claim(the_object: &Value) -> Result<()> {
        match the_object {
            Value::Object(obj) => {
                for (key, value) in obj.iter() {
                    if key == SD_DIGESTS_KEY || key == SD_LIST_PREFIX {
                        return Err(Error::DataFieldMismatch(format!(
                            "Claim object cannot have `{}` field",
                            key
                        )));
                    } else {
                        Self::check_for_sd_claim(value)?;
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    Self::check_for_sd_claim(item)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn parse_compact_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        let parts: Vec<&str> = sd_jwt_with_disclosures
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        if parts.len() < 2 {
            // minimal number of SD-JWT parts according to the standard
            return Err(Error::InvalidInput(format!(
                "Invalid SD-JWT length: {}",
                parts.len()
            )));
        }
        let mut parts = parts.into_iter();
        let sd_jwt = parts.next().ok_or(Error::IndexOutOfBounds {
            idx: 0,
            length: parts.len(),
            msg: format!("Invalid SD-JWT: {}", sd_jwt_with_disclosures),
        })?;
        self.sign_alg = Self::decode_header_and_get_sign_algorithm(sd_jwt);
        let trailing = parts.next_back().unwrap_or("");
        self.unverified_input_key_binding_jwt = if trailing.is_empty() {
            None
        } else {
            Some(trailing.to_owned())
        };
        self.input_disclosures = parts.map(str::to_owned).collect();
        self.unverified_sd_jwt = Some(sd_jwt.to_owned());

        let mut sd_jwt = sd_jwt.split(JWT_SEPARATOR);
        sd_jwt.next();
        let jwt_body = sd_jwt.next().ok_or(Error::IndexOutOfBounds {
            idx: 1,
            length: 3,
            msg: format!(
                "Invalid JWT: Cannot extract JWT payload: {}",
                self.unverified_sd_jwt.to_owned().unwrap_or("".to_string())
            ),
        })?;
        self.unverified_input_sd_jwt_payload = Some(jwt_payload_decode(jwt_body)?);
        Ok(())
    }

    fn parse_flattened_json_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        let parsed: SDJWTFlattenedJson = serde_json::from_str(&sd_jwt_with_disclosures)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        self.unverified_input_key_binding_jwt = parsed.header.kb_jwt;
        self.input_disclosures = parsed.header.disclosures;
        self.unverified_input_sd_jwt_payload = Some(jwt_payload_decode(&parsed.payload)?);
        let sd_jwt = format!(
            "{}.{}.{}",
            parsed.protected, parsed.payload, parsed.signature
        );
        self.unverified_sd_jwt = Some(sd_jwt.clone());
        self.sign_alg = Self::decode_header_and_get_sign_algorithm(&sd_jwt);
        Ok(())
    }

    fn parse_general_json_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        let parsed: SDJWTGeneralJson = serde_json::from_str(&sd_jwt_with_disclosures)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        if parsed.signatures.len() > 1 {
            return Err(Error::InvalidInput(
                "General JSON SD-JWT with multiple signatures is not supported yet".to_string(),
            ));
        }
        // RFC 9901 §8.3: in General JSON Serialization, the Disclosures and the
        // optional KB-JWT live in the first signature's unprotected header.
        let signature = parsed
            .signatures
            .into_iter()
            .next()
            .ok_or(Error::InvalidInput(
                "General JSON SD-JWT must contain at least one signature".to_string(),
            ))?;
        self.unverified_input_key_binding_jwt = signature.header.kb_jwt;
        self.input_disclosures = signature.header.disclosures;
        self.unverified_input_sd_jwt_payload = Some(jwt_payload_decode(&parsed.payload)?);
        let sd_jwt = format!(
            "{}.{}.{}",
            signature.protected, parsed.payload, signature.signature
        );
        self.unverified_sd_jwt = Some(sd_jwt.clone());
        self.sign_alg = Self::decode_header_and_get_sign_algorithm(&sd_jwt);
        Ok(())
    }

    fn parse_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        match self.serialization_format {
            SDJWTSerializationFormat::Compact => self.parse_compact_sd_jwt(sd_jwt_with_disclosures),
            SDJWTSerializationFormat::FlattenedJson => {
                self.parse_flattened_json_sd_jwt(sd_jwt_with_disclosures)
            }
            SDJWTSerializationFormat::GeneralJson => {
                self.parse_general_json_sd_jwt(sd_jwt_with_disclosures)
            }
        }
    }
    /// Decodes a header jwt string and extracts the "alg" field from the JSON object.
    /// # Arguments
    /// * `sd_jwt` - jwt format string.
    /// # Returns
    /// * `Option<String>` - The result containing the algorithm String e.g ES256 or on failure None.
    fn decode_header_and_get_sign_algorithm(sd_jwt: &str) -> Option<String> {
        let parts: Vec<&str> = sd_jwt.split('.').collect();
        if parts.len() < 2 {
            return None;
        }
        let jwt_header = parts[0];
        let decoded = base64url_decode(jwt_header).ok()?;
        let decoded_str = std::str::from_utf8(&decoded).ok()?;
        let json_sign_alg: Value = serde_json::from_str(decoded_str).ok()?;
        let sign_alg = json_sign_alg
            .get("alg")
            .and_then(Value::as_str)
            .map(String::from);
        sign_alg
    }

    /// Splits a signed JWT (`protected.payload.signature`) into its three parts.
    fn split_jwt(jwt: &str) -> Result<(String, String, String)> {
        let parts: Vec<&str> = jwt.split('.').collect();
        let [protected, payload, signature] = parts.as_slice() else {
            return Err(Error::InvalidState(format!(
                "Invalid signed JWT, expected three parts: {jwt}"
            )));
        };
        Ok((
            protected.to_string(),
            payload.to_string(),
            signature.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{error::Error, utils, SDJWTCommon};
    use serde_json::json;

    const OBJECT_DISCLOSURE: &str = "WyJzYWx0IiwibmFtZSIseyJyb2xlIjoiYWRtaW4ifV0";
    const OBJECT_DISCLOSURE_HASH: &str = "UIToslcm0Y9tZh7-6HTCY9UQjI_duhh-wnQtQX9yfqQ";
    const WHITESPACE_DISCLOSURE: &str = "WyJzYWx0IiwgIm5hbWUiLCB7InJvbGUiOiAiYWRtaW4ifV0";
    const WHITESPACE_DISCLOSURE_HASH: &str = "heY8-8zXVWlYO5sT5PWM6IQGEGJcyW_aTHm-2D1DgTQ";
    const ARRAY_DISCLOSURE: &str = "WyJhcnJheS1zYWx0Iiw0Ml0";
    const ARRAY_DISCLOSURE_HASH: &str = "GiEJkgij2cXW0bIMz3Fwi09P0ZQLSXzQ-1CpxGGfl98";
    const INVALID_BASE64_DISCLOSURE: &str = "%";
    const INVALID_BASE64_MESSAGE: &str =
        "Error decoding disclosure %: invalid input: Invalid byte 37, offset 0.";
    const INVALID_JSON_DISCLOSURE: &str = "ew";
    const INVALID_JSON_MESSAGE: &str =
        "Error parsing disclosure ew: EOF while parsing an object at line 1 column 1";

    fn common_with_disclosures(disclosures: &[&str]) -> SDJWTCommon {
        SDJWTCommon {
            input_disclosures: disclosures
                .iter()
                .map(|disclosure| (*disclosure).to_owned())
                .collect(),
            ..Default::default()
        }
    }

    fn assert_invalid_disclosure(error: Error, expected_message: &str) {
        assert_eq!(
            error.to_string(),
            format!("invalid disclosure: {expected_message}")
        );
        match error {
            Error::InvalidDisclosure(message) => assert_eq!(message, expected_message),
            other => panic!("expected InvalidDisclosure, got {other:?}"),
        }
    }

    fn assert_duplicate_disclosure(error: Error) {
        assert_eq!(
            error.to_string(),
            format!("Digest {OBJECT_DISCLOSURE_HASH} appears multiple times")
        );
        match error {
            Error::DuplicateDigestError(digest) => {
                assert_eq!(digest, OBJECT_DISCLOSURE_HASH)
            }
            other => panic!("expected DuplicateDigestError, got {other:?}"),
        }
    }

    #[test]
    fn create_hash_mappings_preserves_exact_raw_hash_and_decoded_values() {
        let mut sdjwt = common_with_disclosures(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);

        sdjwt.create_hash_mappings().unwrap();

        assert_eq!(sdjwt.hash_to_decoded_disclosure.len(), 2);
        assert_eq!(sdjwt.hash_to_disclosure.len(), 2);
        assert_eq!(
            sdjwt.ordered_disclosure_digests,
            [OBJECT_DISCLOSURE_HASH, ARRAY_DISCLOSURE_HASH]
        );
        assert_eq!(
            sdjwt.hash_to_decoded_disclosure.get(OBJECT_DISCLOSURE_HASH),
            Some(&json!(["salt", "name", { "role": "admin" }]))
        );
        assert_eq!(
            sdjwt.hash_to_decoded_disclosure.get(ARRAY_DISCLOSURE_HASH),
            Some(&json!(["array-salt", 42]))
        );
        assert_eq!(
            sdjwt
                .hash_to_disclosure
                .get(OBJECT_DISCLOSURE_HASH)
                .map(String::as_str),
            Some(OBJECT_DISCLOSURE)
        );
        assert_eq!(
            sdjwt
                .hash_to_disclosure
                .get(ARRAY_DISCLOSURE_HASH)
                .map(String::as_str),
            Some(ARRAY_DISCLOSURE)
        );
    }

    #[test]
    fn create_hash_mappings_hashes_original_encoded_disclosure_bytes() {
        let mut sdjwt = common_with_disclosures(&[OBJECT_DISCLOSURE, WHITESPACE_DISCLOSURE]);

        sdjwt.create_hash_mappings().unwrap();

        let compact = sdjwt
            .hash_to_decoded_disclosure
            .get(OBJECT_DISCLOSURE_HASH)
            .unwrap();
        let spaced = sdjwt
            .hash_to_decoded_disclosure
            .get(WHITESPACE_DISCLOSURE_HASH)
            .unwrap();
        assert_eq!(compact, spaced);
        assert_ne!(OBJECT_DISCLOSURE, WHITESPACE_DISCLOSURE);
        assert_ne!(OBJECT_DISCLOSURE_HASH, WHITESPACE_DISCLOSURE_HASH);
        assert_eq!(
            sdjwt
                .hash_to_disclosure
                .get(OBJECT_DISCLOSURE_HASH)
                .map(String::as_str),
            Some(OBJECT_DISCLOSURE)
        );
        assert_eq!(
            sdjwt
                .hash_to_disclosure
                .get(WHITESPACE_DISCLOSURE_HASH)
                .map(String::as_str),
            Some(WHITESPACE_DISCLOSURE)
        );
    }

    #[test]
    fn create_hash_mappings_reports_invalid_base64_variant_and_message() {
        let mut sdjwt = common_with_disclosures(&[INVALID_BASE64_DISCLOSURE]);

        let error = sdjwt.create_hash_mappings().unwrap_err();

        assert_invalid_disclosure(error, INVALID_BASE64_MESSAGE);
    }

    #[test]
    fn create_hash_mappings_reports_invalid_json_variant_and_message() {
        let mut sdjwt = common_with_disclosures(&[INVALID_JSON_DISCLOSURE]);

        let error = sdjwt.create_hash_mappings().unwrap_err();

        assert_invalid_disclosure(error, INVALID_JSON_MESSAGE);
    }

    #[test]
    fn create_hash_mappings_rejects_duplicate_presented_disclosure() {
        let mut sdjwt = common_with_disclosures(&[OBJECT_DISCLOSURE, OBJECT_DISCLOSURE]);

        let error = sdjwt.create_hash_mappings().unwrap_err();

        assert_duplicate_disclosure(error);
    }

    #[test]
    fn create_hash_mappings_preserves_mixed_fault_input_order() {
        for (disclosures, expected_message) in [
            (
                vec![INVALID_BASE64_DISCLOSURE, INVALID_JSON_DISCLOSURE],
                Some(INVALID_BASE64_MESSAGE),
            ),
            (
                vec![INVALID_JSON_DISCLOSURE, INVALID_BASE64_DISCLOSURE],
                Some(INVALID_JSON_MESSAGE),
            ),
            (
                vec![
                    INVALID_BASE64_DISCLOSURE,
                    OBJECT_DISCLOSURE,
                    OBJECT_DISCLOSURE,
                ],
                Some(INVALID_BASE64_MESSAGE),
            ),
            (
                vec![
                    INVALID_JSON_DISCLOSURE,
                    OBJECT_DISCLOSURE,
                    OBJECT_DISCLOSURE,
                ],
                Some(INVALID_JSON_MESSAGE),
            ),
            (
                vec![
                    OBJECT_DISCLOSURE,
                    OBJECT_DISCLOSURE,
                    INVALID_BASE64_DISCLOSURE,
                ],
                None,
            ),
            (
                vec![
                    OBJECT_DISCLOSURE,
                    OBJECT_DISCLOSURE,
                    INVALID_JSON_DISCLOSURE,
                ],
                None,
            ),
        ] {
            let mut sdjwt = common_with_disclosures(&disclosures);
            let error = sdjwt.create_hash_mappings().unwrap_err();

            if let Some(expected_message) = expected_message {
                assert_invalid_disclosure(error, expected_message);
            } else {
                assert_duplicate_disclosure(error);
            }
        }
    }

    #[test]
    fn create_hash_mappings_clears_stale_mappings_for_empty_input() {
        let mut sdjwt = SDJWTCommon::default();
        sdjwt
            .hash_to_decoded_disclosure
            .insert("stale".to_owned(), json!(["stale"]));
        sdjwt
            .hash_to_disclosure
            .insert("stale".to_owned(), "stale".to_owned());
        sdjwt.ordered_disclosure_digests.push("stale".to_owned());

        sdjwt.create_hash_mappings().unwrap();

        assert!(sdjwt.hash_to_decoded_disclosure.is_empty());
        assert!(sdjwt.hash_to_disclosure.is_empty());
        assert!(sdjwt.ordered_disclosure_digests.is_empty());
        assert!(sdjwt.input_disclosures.is_empty());
    }

    #[test]
    fn create_hash_mappings_does_not_mutate_input_on_success_or_failure() {
        for disclosures in [
            vec![OBJECT_DISCLOSURE, ARRAY_DISCLOSURE],
            vec![OBJECT_DISCLOSURE, INVALID_JSON_DISCLOSURE],
        ] {
            let mut sdjwt = common_with_disclosures(&disclosures);
            let original = sdjwt.input_disclosures.clone();

            let _ = sdjwt.create_hash_mappings();

            assert_eq!(sdjwt.input_disclosures, original);
        }
    }

    #[test]
    fn create_hash_mappings_does_not_publish_partial_mappings_on_failure() {
        let mut sdjwt = common_with_disclosures(&[OBJECT_DISCLOSURE, INVALID_JSON_DISCLOSURE]);

        let error = sdjwt.create_hash_mappings().unwrap_err();

        assert_invalid_disclosure(error, INVALID_JSON_MESSAGE);
        assert!(sdjwt.hash_to_decoded_disclosure.is_empty());
        assert!(sdjwt.hash_to_disclosure.is_empty());
        assert!(sdjwt.ordered_disclosure_digests.is_empty());
    }

    #[test]
    fn test_parse_compact_sd_jwt() {
        let mut sdjwt = SDJWTCommon::default();
        let encoded_empty_object = utils::base64url_encode("{}".as_bytes());
        sdjwt
            .parse_compact_sd_jwt(format!(
                "jwt1.{encoded_empty_object}.jwt3~disc1~disc2~kbjwt"
            ))
            .unwrap();
        assert_eq!(
            sdjwt.unverified_sd_jwt.unwrap(),
            format!("jwt1.{encoded_empty_object}.jwt3")
        );
        assert_eq!(
            sdjwt.unverified_input_key_binding_jwt.as_deref(),
            Some("kbjwt")
        );
        assert_eq!(
            sdjwt.input_disclosures,
            vec!["disc1".to_string(), "disc2".to_string()]
        );

        let mut sdjwt = SDJWTCommon::default();
        sdjwt
            .parse_compact_sd_jwt(format!("jwt1.{encoded_empty_object}.jwt3~disc1~disc2~"))
            .unwrap();
        assert!(sdjwt.unverified_input_key_binding_jwt.is_none());
        assert_eq!(
            sdjwt.input_disclosures,
            vec!["disc1".to_string(), "disc2".to_string()]
        );
    }

    #[test]
    fn test_parse_flattened_json_sd_jwt() {
        let mut sdjwt = SDJWTCommon::default();
        let encoded_empty_object = utils::base64url_encode("{}".as_bytes());
        sdjwt.parse_flattened_json_sd_jwt(format!(
            r#"{{"protected":"jwt1","payload":"{encoded_empty_object}","signature":"jwt3","header":{{"disclosures":["disc1","disc2"],"kb_jwt":"kbjwt"}}}}"#
        )).unwrap();
        assert_eq!(
            sdjwt.unverified_sd_jwt.unwrap(),
            format!("jwt1.{encoded_empty_object}.jwt3")
        );
        assert_eq!(sdjwt.unverified_input_key_binding_jwt.unwrap(), "kbjwt");
        assert_eq!(
            sdjwt.input_disclosures,
            vec!["disc1".to_string(), "disc2".to_string()]
        );
    }

    #[test]
    fn test_parse_general_json_rejects_empty_signatures() {
        // `signatures` is a Vec, so serde accepts `[]`; the parser must reject a
        // signature-less input explicitly rather than panic on `signatures[0]`.
        let mut sdjwt = SDJWTCommon::default();
        let err = sdjwt
            .parse_general_json_sd_jwt(r#"{"payload":"e30","signatures":[]}"#.to_string())
            .unwrap_err();
        assert!(
            format!("{err}").contains("at least one signature"),
            "empty `signatures` array should be rejected: {err}"
        );
    }

    #[test]
    fn test_disallow_reserved_words_as_claim_names() {
        for (claims, reserved) in [
            (json!({ "_sd": "x" }), "_sd"),
            (json!({ "...": "x" }), "..."),
        ] {
            let err = SDJWTCommon::check_for_sd_claim(&claims).unwrap_err();
            assert!(
                format!("{err}").contains("cannot have"),
                "reserved word `{reserved}` was allowed as a claim name: {err}"
            );
        }
        assert!(
            SDJWTCommon::check_for_sd_claim(&json!({ "address": { "street": "x" } })).is_ok(),
            "a claim object without reserved words was rejected"
        );
    }
}
