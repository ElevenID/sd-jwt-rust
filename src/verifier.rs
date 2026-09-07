// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use crate::error::{Error, DUPLICATE_DISCLOSURE_DIGEST};
use crate::SDJWTSerializationFormat;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::ops::Add;
use std::option::Option;
use std::str::FromStr;
use std::string::String;
use std::vec::Vec;

use crate::utils::base64_hash;
use crate::{
    FallibleKeyResolver, KeyResolver, SDJWTCommon, VerificationPolicy, CNF_KEY,
    COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DEFAULT_DIGEST_ALG, DIGEST_ALG_KEY, JWK_KEY,
    KB_DIGEST_KEY, KB_JWT_TYP_HEADER, SD_DIGESTS_KEY, SD_LIST_PREFIX,
};

const DISCLOSURE_PREPROCESSING_STATE_FAILURE: &str =
    "Disclosure preprocessing state is inconsistent";
const MAX_PROCESSED_SD_JWT_DEPTH: usize = 128;
const PROCESSED_SD_JWT_DEPTH_FAILURE: &str =
    "Processed SD-JWT exceeds maximum supported nesting depth";
const INVALID_OBJECT_DISCLOSURE_TYPE: &str = "Object-property Disclosure must be a JSON array";
const INVALID_OBJECT_DISCLOSURE_LENGTH: &str =
    "Object-property Disclosure must be a 3-element array [salt, name, value]";
const RESERVED_DISCLOSURE_CLAIM_NAME: &str =
    "Disclosure claim name must not use a reserved SD-JWT structural marker";
const INVALID_ARRAY_DISCLOSURE_TYPE: &str = "Array-element Disclosure must be a JSON array";
const INVALID_ARRAY_DISCLOSURE_LENGTH: &str =
    "Array-element Disclosure must be a 2-element array [salt, value]";
const INVALID_DIGEST_ALGORITHM: &str = "SD-JWT digest algorithm is not supported";
const UNREFERENCED_DISCLOSURE: &str = "Disclosure was not referenced by the SD-JWT";
const DUPLICATE_DISCLOSED_CLAIM: &str = "Duplicate disclosed claim";

pub struct SDJWTVerifier {
    sd_jwt_engine: SDJWTCommon,

    sd_jwt_payload: Map<String, Value>,
    _holder_public_key_payload: Option<Map<String, Value>>,
    duplicate_hash_check: HashSet<String>,
    pub verified_claims: Value,

    cb_get_issuer_key: Box<FallibleKeyResolver>,
    verification_policy: VerificationPolicy,
}

impl SDJWTVerifier {
    /// Create a new SDJWTVerifier instance.
    ///
    /// # Arguments
    /// * `sd_jwt_presentation` - The SD-JWT presentation to verify.
    /// * `cb_get_issuer_key` - A callback function that takes the issuer and the header of the SD-JWT and returns the public key of the issuer.
    /// * `expected_aud` - The expected audience of the SD-JWT.
    /// * `expected_nonce` - The expected nonce of the SD-JWT.
    /// * `serialization_format` - The serialization format of the SD-JWT, see [SDJWTSerializationFormat].
    ///
    /// # Returns
    /// * `SDJWTVerifier` - The SDJWTVerifier instance. The verified claims can be accessed via the `verified_claims` property.
    pub fn new(
        sd_jwt_presentation: String,
        cb_get_issuer_key: Box<KeyResolver>,
        expected_aud: Option<String>,
        expected_nonce: Option<String>,
        serialization_format: SDJWTSerializationFormat,
    ) -> Result<Self> {
        Self::new_with_policy(
            sd_jwt_presentation,
            Box::new(move |issuer, header| Ok(cb_get_issuer_key(issuer, header))),
            expected_aud,
            expected_nonce,
            serialization_format,
            VerificationPolicy::default(),
        )
    }

    /// Verify with a fallible key resolver and an explicit JOSE algorithm policy.
    pub fn new_with_policy(
        sd_jwt_presentation: String,
        cb_get_issuer_key: Box<FallibleKeyResolver>,
        expected_aud: Option<String>,
        expected_nonce: Option<String>,
        serialization_format: SDJWTSerializationFormat,
        verification_policy: VerificationPolicy,
    ) -> Result<Self> {
        let mut verifier = SDJWTVerifier {
            sd_jwt_payload: serde_json::Map::new(),
            _holder_public_key_payload: None,
            duplicate_hash_check: HashSet::new(),
            cb_get_issuer_key,
            verification_policy,
            sd_jwt_engine: SDJWTCommon {
                serialization_format,
                ..Default::default()
            },
            verified_claims: Value::Null,
        };

        verifier.sd_jwt_engine.parse_sd_jwt(sd_jwt_presentation)?;
        verifier.sd_jwt_engine.create_verifier_hash_mappings()?;
        let sign_alg = verifier.sd_jwt_engine.sign_alg.clone();
        verifier.verify_sd_jwt(sign_alg.clone())?;
        verifier.verified_claims = verifier.extract_sd_claims()?;

        if let (Some(expected_aud), Some(expected_nonce)) = (&expected_aud, &expected_nonce) {
            verifier.verify_key_binding_jwt(expected_aud.to_owned(), expected_nonce.to_owned())?;
        } else if expected_aud.is_some() || expected_nonce.is_some() {
            return Err(Error::InvalidInput(
                "Either both expected_aud and expected_nonce must be provided or both must be None"
                    .to_string(),
            ));
        }

        Ok(verifier)
    }

    fn verify_sd_jwt(&mut self, sign_alg: Option<String>) -> Result<()> {
        let sd_jwt = self
            .sd_jwt_engine
            .unverified_sd_jwt
            .as_ref()
            .ok_or(Error::ConversionError("reference".to_string()))?;
        let parsed_header_sd_jwt = jsonwebtoken::decode_header(sd_jwt)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;

        let algorithm = parsed_header_sd_jwt.alg;
        if !self.verification_policy.allows(algorithm) {
            return Err(Error::InvalidInput(format!(
                "Issuer-signed JWT algorithm {algorithm:?} is not allowed by verification policy"
            )));
        }
        let declared_algorithm = sign_alg.ok_or_else(|| {
            Error::InvalidInput(
                "Issuer-signed JWT header is missing the `alg` parameter".to_string(),
            )
        })?;
        let decoded_algorithm = Algorithm::from_str(&declared_algorithm)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        if decoded_algorithm != algorithm {
            return Err(Error::InvalidInput(
                "Issuer-signed JWT algorithm metadata is inconsistent".to_string(),
            ));
        }

        let unverified_issuer = self
            .sd_jwt_engine
            .unverified_input_sd_jwt_payload
            .as_ref()
            .ok_or(Error::ConversionError("reference".to_string()))?["iss"]
            .as_str()
            .ok_or(Error::ConversionError("str".to_string()))?;
        let issuer_public_key = (self.cb_get_issuer_key)(unverified_issuer, &parsed_header_sd_jwt)?;
        let mut validation = Validation::new(algorithm);
        // RFC 9901 §4.1: `exp` is not mandated, so don't require it. `validate_exp`
        // stays true, so a present `exp` is still checked for expiry.
        validation.required_spec_claims.remove("exp");
        // `nbf` is optional too (not added to required_spec_claims), but when
        // present it must be honored; jsonwebtoken leaves `validate_nbf` off.
        validation.validate_nbf = true;
        let claims = jsonwebtoken::decode(sd_jwt, &issuer_public_key, &validation)
            .map_err(|e| Error::DeserializationError(format!("Cannot decode jwt: {e}")))?
            .claims;
        crate::validate_public_confirmation_claim(&claims)?;

        self.sd_jwt_payload = claims;
        self._holder_public_key_payload = self
            .sd_jwt_payload
            .get(CNF_KEY)
            .and_then(Value::as_object)
            .cloned();

        Ok(())
    }

    fn verify_key_binding_jwt(
        &mut self,
        expected_aud: String,
        expected_nonce: String,
    ) -> Result<()> {
        let holder_public_key_payload_jwk = match &self._holder_public_key_payload {
            None => {
                return Err(Error::KeyNotFound(
                    "No holder public key in SD-JWT".to_string(),
                ));
            }
            Some(payload) => {
                if let Some(jwk) = payload.get(JWK_KEY) {
                    jwk.clone()
                } else {
                    return Err(Error::InvalidInput("The holder_public_key_payload is malformed. It doesn't contain the claim jwk".to_string()));
                }
            }
        };
        let pubkey: DecodingKey = match serde_json::from_value::<Jwk>(holder_public_key_payload_jwk)
        {
            Ok(jwk) => {
                if let Ok(pubkey) = DecodingKey::from_jwk(&jwk) {
                    pubkey
                } else {
                    return Err(Error::DeserializationError(
                        "Cannot parse DecodingKey from json".to_string(),
                    ));
                }
            }
            Err(_) => {
                return Err(Error::DeserializationError(
                    "Cannot parse JWK from json".to_string(),
                ));
            }
        };
        let key_binding_jwt = match &self.sd_jwt_engine.unverified_input_key_binding_jwt {
            Some(payload) => {
                let header = jsonwebtoken::decode_header(payload)
                    .map_err(|e| Error::DeserializationError(e.to_string()))?;
                if !self.verification_policy.allows(header.alg) {
                    return Err(Error::InvalidInput(format!(
                        "Key Binding JWT algorithm {:?} is not allowed by verification policy",
                        header.alg
                    )));
                }
                let mut validation = Validation::new(header.alg);
                validation.set_audience(&[&expected_aud]);
                validation.set_required_spec_claims(&["aud"]);

                jsonwebtoken::decode::<Map<String, Value>>(&payload, &pubkey, &validation)
                    .map_err(|e| Error::DeserializationError(e.to_string()))?
            }
            None => {
                return Err(Error::InvalidState(
                    "Cannot take Key Binding JWK from String".to_string(),
                ));
            }
        };
        if key_binding_jwt.header.typ != Some(KB_JWT_TYP_HEADER.to_string()) {
            return Err(Error::InvalidInput("Invalid header type".to_string()));
        }
        if key_binding_jwt.claims.get("nonce") != Some(&Value::String(expected_nonce)) {
            return Err(Error::InvalidInput("Invalid nonce".to_string()));
        }
        if !key_binding_jwt.claims.contains_key("iat") {
            return Err(Error::InvalidInput(
                "Missing required `iat` claim in KB-JWT".to_string(),
            ));
        }
        let sd_hash = self._get_key_binding_digest_hash()?;
        if key_binding_jwt.claims.get(KB_DIGEST_KEY) != Some(&Value::String(sd_hash)) {
            return Err(Error::InvalidInput("Invalid digest in KB-JWT".to_string()));
        }

        Ok(())
    }

    fn _get_key_binding_digest_hash(&mut self) -> Result<String> {
        let mut combined: Vec<&str> =
            Vec::with_capacity(self.sd_jwt_engine.input_disclosures.len() + 1);
        combined.push(
            self.sd_jwt_engine
                .unverified_sd_jwt
                .as_ref()
                .ok_or(Error::ConversionError("reference".to_string()))?,
        );
        combined.extend(
            self.sd_jwt_engine
                .input_disclosures
                .iter()
                .map(|s| s.as_str()),
        );
        let combined = combined
            .join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .add(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);

        Ok(base64_hash(combined.as_bytes()))
    }

    fn extract_sd_claims(&mut self) -> Result<Value> {
        if self.sd_jwt_payload.contains_key(DIGEST_ALG_KEY)
            && self.sd_jwt_payload[DIGEST_ALG_KEY] != DEFAULT_DIGEST_ALG
        {
            return Err(Error::DeserializationError(
                INVALID_DIGEST_ALGORITHM.to_owned(),
            ));
        }

        for (key, value) in self.sd_jwt_payload.iter() {
            if key == DIGEST_ALG_KEY {
                continue;
            }
            Self::reject_nested_sd_alg(value)?;
        }

        self.duplicate_hash_check =
            HashSet::with_capacity(self.sd_jwt_engine.input_disclosures.len());
        let claims: Value = self.sd_jwt_payload.clone().into_iter().collect();
        let unpacked = self.unpack_disclosed_claims(&claims, 0)?;

        if self.sd_jwt_engine.ordered_disclosure_digests.len()
            != self.sd_jwt_engine.input_disclosures.len()
        {
            return Err(Error::InvalidState(
                DISCLOSURE_PREPROCESSING_STATE_FAILURE.to_owned(),
            ));
        }

        // Draft-07 section 8.1 step 5: if any presented Disclosure was not
        // referenced by digest value in the Issuer-signed JWT (directly or
        // recursively via other Disclosures), the SD-JWT MUST be rejected.
        // `duplicate_hash_check` accumulates every digest encountered during
        // the recursive unpack, so any disclosure whose hash is absent from
        // that set is unreferenced.
        for disclosure_hash in &self.sd_jwt_engine.ordered_disclosure_digests {
            if !self.duplicate_hash_check.contains(disclosure_hash.as_str()) {
                return Err(Error::InvalidDisclosure(UNREFERENCED_DISCLOSURE.to_owned()));
            }
        }

        Ok(unpacked)
    }

    fn reject_nested_sd_alg(value: &Value) -> Result<()> {
        match value {
            Value::Object(obj) => {
                if obj.contains_key(DIGEST_ALG_KEY) {
                    return Err(Error::DataFieldMismatch(format!(
                        "`{DIGEST_ALG_KEY}` is only allowed at the top level of the SD-JWT payload"
                    )));
                }
                obj.values().try_for_each(Self::reject_nested_sd_alg)
            }
            Value::Array(arr) => arr.iter().try_for_each(Self::reject_nested_sd_alg),
            _ => Ok(()),
        }
    }

    fn record_digest(&mut self, digest: &str) -> Result<()> {
        if self.duplicate_hash_check.contains(digest) {
            return Err(Error::DuplicateDigestError(
                DUPLICATE_DISCLOSURE_DIGEST.to_owned(),
            ));
        }
        self.duplicate_hash_check.insert(digest.to_owned());
        Ok(())
    }

    fn unpack_disclosed_claims(
        &mut self,
        sd_jwt_claims: &Value,
        processed_depth: usize,
    ) -> Result<Value> {
        match sd_jwt_claims {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                Ok(sd_jwt_claims.to_owned())
            }
            Value::Array(arr) => {
                let processed_depth = Self::enter_processed_container(processed_depth)?;
                self.unpack_disclosed_claims_in_array(arr, processed_depth)
            }
            Value::Object(obj) => {
                let processed_depth = Self::enter_processed_container(processed_depth)?;
                self.unpack_disclosed_claims_in_object(obj, processed_depth)
            }
        }
    }

    fn enter_processed_container(processed_depth: usize) -> Result<usize> {
        let next_depth = processed_depth
            .checked_add(1)
            .ok_or_else(|| Error::InvalidDisclosure(PROCESSED_SD_JWT_DEPTH_FAILURE.to_owned()))?;
        if next_depth > MAX_PROCESSED_SD_JWT_DEPTH {
            return Err(Error::InvalidDisclosure(
                PROCESSED_SD_JWT_DEPTH_FAILURE.to_owned(),
            ));
        }
        Ok(next_depth)
    }

    fn unpack_disclosed_claims_in_array(
        &mut self,
        arr: &Vec<Value>,
        processed_depth: usize,
    ) -> Result<Value> {
        if arr.is_empty() {
            return Err(Error::InvalidArrayDisclosureObject(
                "Array of disclosed claims cannot be empty".to_string(),
            ));
        }

        let mut claims = vec![];
        for value in arr {
            match value {
                // case for SD objects in arrays
                Value::Object(obj) if obj.contains_key(SD_LIST_PREFIX) => {
                    if obj.len() > 1 {
                        return Err(Error::InvalidDisclosure(
                            "Disclosed claim object in an array maust contain only one key"
                                .to_string(),
                        ));
                    }

                    let digest = obj.get(SD_LIST_PREFIX).unwrap();
                    let disclosed_claim = self.unpack_from_digest(digest, processed_depth)?;
                    if let Some(disclosed_claim) = disclosed_claim {
                        claims.push(disclosed_claim);
                    }
                }
                _ => {
                    let claim = self.unpack_disclosed_claims(value, processed_depth)?;
                    claims.push(claim);
                }
            }
        }
        Ok(Value::Array(claims))
    }

    fn unpack_disclosed_claims_in_object(
        &mut self,
        nested_sd_jwt_claims: &Map<String, Value>,
        processed_depth: usize,
    ) -> Result<Value> {
        let mut disclosed_claims: Map<String, Value> = serde_json::Map::new();

        for (key, value) in nested_sd_jwt_claims {
            if key != SD_DIGESTS_KEY && key != DIGEST_ALG_KEY {
                disclosed_claims.insert(
                    key.to_owned(),
                    self.unpack_disclosed_claims(value, processed_depth)?,
                );
            }
        }

        if let Some(Value::Array(digest_of_disclosures)) = nested_sd_jwt_claims.get(SD_DIGESTS_KEY)
        {
            self.unpack_from_digests(
                &mut disclosed_claims,
                digest_of_disclosures,
                processed_depth,
            )?;
        }

        Ok(Value::Object(disclosed_claims))
    }

    fn unpack_from_digests(
        &mut self,
        pre_output: &mut Map<String, Value>,
        digests_of_disclosures: &Vec<Value>,
        processed_depth: usize,
    ) -> Result<()> {
        for digest in digests_of_disclosures {
            let digest = digest
                .as_str()
                .ok_or(Error::ConversionError("str".to_string()))?;
            self.record_digest(digest)?;

            if let Some(value_for_digest) =
                self.sd_jwt_engine.hash_to_decoded_disclosure.get(digest)
            {
                let disclosure = value_for_digest.as_array().ok_or_else(|| {
                    Error::InvalidArrayDisclosureObject(INVALID_OBJECT_DISCLOSURE_TYPE.to_owned())
                })?;
                if disclosure.len() != 3 {
                    return Err(Error::InvalidDisclosure(
                        INVALID_OBJECT_DISCLOSURE_LENGTH.to_owned(),
                    ));
                }
                let key = disclosure[1]
                    .as_str()
                    .ok_or(Error::ConversionError("str".to_string()))?
                    .to_owned();
                if key == SD_DIGESTS_KEY || key == SD_LIST_PREFIX {
                    return Err(Error::InvalidDisclosure(
                        RESERVED_DISCLOSURE_CLAIM_NAME.to_owned(),
                    ));
                }
                let value = disclosure[2].clone();
                if pre_output.contains_key(&key) {
                    return Err(Error::DuplicateKeyError(
                        DUPLICATE_DISCLOSED_CLAIM.to_owned(),
                    ));
                }
                let unpacked_value = self.unpack_disclosed_claims(&value, processed_depth)?;
                pre_output.insert(key, unpacked_value);
            }
        }

        Ok(())
    }

    fn unpack_from_digest(
        &mut self,
        digest: &Value,
        processed_depth: usize,
    ) -> Result<Option<Value>> {
        let digest = digest
            .as_str()
            .ok_or(Error::ConversionError("str".to_string()))?;
        self.record_digest(digest)?;

        if let Some(value_for_digest) = self.sd_jwt_engine.hash_to_decoded_disclosure.get(digest) {
            let disclosure = value_for_digest.as_array().ok_or_else(|| {
                Error::InvalidArrayDisclosureObject(INVALID_ARRAY_DISCLOSURE_TYPE.to_owned())
            })?;
            if disclosure.len() != 2 {
                return Err(Error::InvalidArrayDisclosureObject(
                    INVALID_ARRAY_DISCLOSURE_LENGTH.to_owned(),
                ));
            }

            let value = disclosure[1].clone();
            let unpacked_value = self.unpack_disclosed_claims(&value, processed_depth)?;
            return Ok(Some(unpacked_value));
        }

        Ok(None)
    }
}

#[cfg(all(test, feature = "holder", feature = "issuer-planning"))]
mod tests {
    use crate::error::Error;
    use crate::issuer::ClaimsForSelectiveDisclosureStrategy;
    use crate::utils::{base64_hash, base64url_decode, base64url_encode};
    use crate::{
        take_disclosure_preprocessing_route, DisclosurePreprocessingRoute, SDJWTFlattenedJson,
        SDJWTGeneralJson, SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat, SDJWTVerifier,
        VerificationPolicy, COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
    };
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
    use rstest::rstest;
    use serde::{ser::SerializeMap, Serialize, Serializer};
    use serde_json::{json, Map, Value};

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";
    const PRIVATE_ISSUER_ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIF93k6rxZ8W38cm0rOwfGdH+YY3k10hP+7gd0falPLg0\ngSEAdW31QyWzfed4EPcw1rYuUa1QU+fXEL0HhdAfYZRkihc=\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_ED25519_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAdW31QyWzfed4EPcw1rYuUa1QU+fXEL0HhdAfYZRkihc=\n-----END PUBLIC KEY-----\n";

    // EdDSA (Ed25519)
    const HOLDER_KEY_ED25519: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOeIDnHHMoPCUTiq206gR+FdCdNtc31SzF1nKX31hvhd\n-----END PRIVATE KEY-----";

    const HOLDER_JWK_KEY_ED25519: &str = r#"{
        "alg": "EdDSA",
        "crv": "Ed25519",
        "kid": "52128f2e-900e-414e-81c3-0b5f86f0f7b3",
        "kty": "OKP",
        "x": "24QLWXJ18wtbg3k_MDGhGM17Xh39UftuxbwJZzRLzkA"
    }"#;

    fn compact_presentation(payload: &Value, disclosures: &[String]) -> String {
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), payload, &issuer_key).unwrap();
        let mut parts = Vec::with_capacity(disclosures.len() + 1);
        parts.push(signed);
        parts.extend(disclosures.iter().cloned());
        format!(
            "{}{}",
            parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR),
            COMBINED_SERIALIZATION_FORMAT_SEPARATOR
        )
    }

    fn serialization_from_compact(presentation: &str, format: SDJWTSerializationFormat) -> String {
        let jwt = presentation.strip_suffix('~').unwrap();
        let mut segments = jwt.split('.');
        let protected = segments.next().unwrap();
        let payload = segments.next().unwrap();
        let signature = segments.next().unwrap();
        assert!(segments.next().is_none());
        match format {
            SDJWTSerializationFormat::Compact => presentation.to_owned(),
            SDJWTSerializationFormat::FlattenedJson => json!({
                "protected": protected,
                "payload": payload,
                "signature": signature,
                "header": {"disclosures": []}
            })
            .to_string(),
            SDJWTSerializationFormat::GeneralJson => json!({
                "payload": payload,
                "signatures": [{
                    "protected": protected,
                    "signature": signature,
                    "header": {"disclosures": []}
                }]
            })
            .to_string(),
        }
    }

    struct DuplicateCnfClaims;

    impl Serialize for DuplicateCnfClaims {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut claims = serializer.serialize_map(Some(4))?;
            claims.serialize_entry("iss", "https://example.com/issuer")?;
            claims.serialize_entry("iat", &1_683_000_000_u64)?;
            claims.serialize_entry("_sd_alg", "sha-256")?;
            claims.serialize_entry("cnf", &DuplicateCnf)?;
            claims.end()
        }
    }

    struct DuplicateCnf;

    impl Serialize for DuplicateCnf {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut confirmation = serializer.serialize_map(Some(1))?;
            confirmation.serialize_entry("jwk", &DuplicateJwk)?;
            confirmation.end()
        }
    }

    struct DuplicateJwk;

    impl Serialize for DuplicateJwk {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut jwk = serializer.serialize_map(Some(4))?;
            jwk.serialize_entry("kty", "EC")?;
            jwk.serialize_entry("kty", "oct")?;
            jwk.serialize_entry("crv", "P-256")?;
            jwk.serialize_entry("x", "AA")?;
            jwk.end()
        }
    }

    fn corrupt_compact_signature(presentation: &str) -> String {
        let (signed, disclosures) = presentation
            .split_once(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .expect("compact test presentation must contain a separator");
        let mut jwt_parts = signed.split('.');
        let protected = jwt_parts.next().unwrap();
        let payload = jwt_parts.next().unwrap();
        assert!(jwt_parts.next().is_some());
        assert!(jwt_parts.next().is_none());
        format!("{protected}.{payload}.AA~{disclosures}")
    }

    fn encoded_disclosure(value: &Value) -> (String, String) {
        let encoded = base64url_encode(&serde_json::to_vec(value).unwrap());
        let digest = base64_hash(encoded.as_bytes());
        (encoded, digest)
    }

    #[derive(Clone, Copy, Debug)]
    enum RecursiveFixtureKind {
        Object,
        Array,
        Alternating,
    }

    #[derive(Clone, Copy)]
    enum RecursiveContainerKind {
        Object,
        Array,
    }

    impl RecursiveFixtureKind {
        fn container_at(self, processed_depth: usize) -> RecursiveContainerKind {
            match self {
                Self::Object => RecursiveContainerKind::Object,
                Self::Array => RecursiveContainerKind::Array,
                Self::Alternating if processed_depth.is_multiple_of(2) => {
                    RecursiveContainerKind::Object
                }
                Self::Alternating => RecursiveContainerKind::Array,
            }
        }
    }

    struct RecursiveDisclosureFixture {
        payload: Value,
        disclosures: Vec<String>,
    }

    impl RecursiveDisclosureFixture {
        fn presentation(&self) -> String {
            compact_presentation(&self.payload, &self.disclosures)
        }
    }

    fn recursive_disclosure_fixture(
        processed_depth: usize,
        fixture_kind: RecursiveFixtureKind,
    ) -> RecursiveDisclosureFixture {
        assert!(processed_depth >= 2);
        let container_kinds = (2..=processed_depth)
            .map(|depth| fixture_kind.container_at(depth))
            .collect::<Vec<_>>();
        let mut disclosures = Vec::with_capacity(container_kinds.len());
        let mut current_value = match container_kinds.last().unwrap() {
            RecursiveContainerKind::Object => json!({"leaf": true}),
            RecursiveContainerKind::Array => json!(["leaf"]),
        };

        for (parent_index, parent_kind) in container_kinds
            .iter()
            .take(container_kinds.len() - 1)
            .enumerate()
            .rev()
        {
            let disclosure = match parent_kind {
                RecursiveContainerKind::Object => json!([
                    format!("recursive-salt-{parent_index}"),
                    format!("recursive-claim-{parent_index}"),
                    current_value,
                ]),
                RecursiveContainerKind::Array => {
                    json!([format!("recursive-salt-{parent_index}"), current_value,])
                }
            };
            let (encoded, digest) = encoded_disclosure(&disclosure);
            disclosures.push(encoded);
            current_value = match parent_kind {
                RecursiveContainerKind::Object => json!({"_sd": [digest]}),
                RecursiveContainerKind::Array => json!([{"...": digest}]),
            };
        }

        let (root_disclosure, root_digest) = encoded_disclosure(&json!([
            "recursive-root-salt",
            "recursive-root",
            current_value,
        ]));
        disclosures.push(root_disclosure);

        RecursiveDisclosureFixture {
            payload: json!({
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "_sd_alg": "sha-256",
                "_sd": [root_digest],
            }),
            disclosures,
        }
    }

    fn composite_depth(value: &Value) -> usize {
        match value {
            Value::Array(values) => {
                1 + values.iter().map(composite_depth).max().unwrap_or_default()
            }
            Value::Object(values) => {
                1 + values
                    .values()
                    .map(composite_depth)
                    .max()
                    .unwrap_or_default()
            }
            _ => 0,
        }
    }

    fn assert_processed_depth_limit(error: Error) {
        match &error {
            Error::InvalidDisclosure(message) => {
                assert_eq!(message, super::PROCESSED_SD_JWT_DEPTH_FAILURE)
            }
            other => panic!("expected InvalidDisclosure depth limit, got {other:?}"),
        }
        assert_eq!(
            error.to_string(),
            format!(
                "invalid disclosure: {}",
                super::PROCESSED_SD_JWT_DEPTH_FAILURE
            )
        );
    }

    fn verify_compact(presentation: String) -> crate::error::Result<SDJWTVerifier> {
        SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
    }

    #[test]
    fn default_policy_rejects_symmetric_algorithm_from_untrusted_header() {
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
        });
        let secret = b"attacker-controlled-shared-secret";
        let signed = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &payload,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let error = SDJWTVerifier::new(
            format!("{signed}~"),
            Box::new(move |_, _| DecodingKey::from_secret(secret)),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
        .err()
        .expect("HS256 must be rejected before signature verification");

        assert!(error
            .to_string()
            .contains("not allowed by verification policy"));
    }

    #[test]
    fn verifier_rejects_signed_private_and_symmetric_confirmation_keys() {
        for private_member in ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            let mut jwk = json!({"kty":"EC", "crv":"P-256", "x":"AA", "y":"AA"});
            jwk.as_object_mut()
                .unwrap()
                .insert(private_member.to_owned(), json!("private-sentinel"));
            let payload = json!({
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "_sd_alg": "sha-256",
                "cnf": {"jwk": jwk}
            });
            let error = compact_verification_error(compact_presentation(&payload, &[]));
            assert!(matches!(
                error,
                Error::InvalidInput(ref message)
                    if message == "cnf.jwk must be a public asymmetric JWK"
            ));
        }

        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "cnf": {"jwk": {"kty":"oct", "k":"private-sentinel"}}
        });
        let compact = compact_presentation(&payload, &[]);
        for format in [
            SDJWTSerializationFormat::Compact,
            SDJWTSerializationFormat::FlattenedJson,
            SDJWTSerializationFormat::GeneralJson,
        ] {
            let presentation = serialization_from_compact(&compact, format.clone());
            let error = SDJWTVerifier::new(
                presentation,
                Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
                None,
                None,
                format,
            )
            .err()
            .expect("symmetric cnf.jwk must be rejected");
            assert!(matches!(error, Error::InvalidInput(_)));
        }
    }

    #[test]
    fn verifier_rejects_signed_duplicate_nested_jwk_members() {
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed = jsonwebtoken::encode(
            &Header::new(Algorithm::ES256),
            &DuplicateCnfClaims,
            &issuer_key,
        )
        .unwrap();
        let error = compact_verification_error(format!("{signed}~"));
        assert!(matches!(
            error,
            Error::DeserializationError(ref message)
                if message.contains("duplicate JSON object member")
        ));
    }

    #[test]
    fn explicit_policy_and_fallible_resolver_fail_closed() {
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
        });
        let presentation = compact_presentation(&payload, &[]);
        let policy = VerificationPolicy::new(vec![Algorithm::ES256]).unwrap();

        let error = SDJWTVerifier::new_with_policy(
            presentation,
            Box::new(|_, _| Err(Error::KeyNotFound("issuer key unavailable".to_string()))),
            None,
            None,
            SDJWTSerializationFormat::Compact,
            policy,
        )
        .err()
        .expect("resolver failure must be propagated");

        assert!(matches!(error, Error::KeyNotFound(_)));
    }

    fn compact_verification_error(presentation: String) -> Error {
        match verify_compact(presentation) {
            Ok(_) => panic!("verifier unexpectedly accepted the test presentation"),
            Err(error) => error,
        }
    }

    #[test]
    fn verifier_construction_uses_adaptive_preprocessing() {
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
        });

        take_disclosure_preprocessing_route();
        verify_compact(compact_presentation(&payload, &[])).unwrap();
        assert_eq!(
            take_disclosure_preprocessing_route(),
            Some(DisclosurePreprocessingRoute::Adaptive)
        );
    }

    #[test]
    fn duplicate_referenced_digest_is_rejected_when_disclosure_is_present_or_absent() {
        let (disclosure, digest) = encoded_disclosure(&json!(["salt", "family_name", "Miller"]));

        for disclosures in [vec![disclosure], Vec::new()] {
            let payload = json!({
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "_sd_alg": "sha-256",
                "_sd": [digest, digest],
            });
            let error = compact_verification_error(compact_presentation(&payload, &disclosures));

            match &error {
                Error::DuplicateDigestError(message) => {
                    assert_eq!(message, super::DUPLICATE_DISCLOSURE_DIGEST)
                }
                other => panic!("expected DuplicateDigestError, got {other:?}"),
            }
            assert!(!error.to_string().contains(&digest));
        }
    }

    #[test]
    fn disclosed_claim_cannot_replace_a_visible_claim() {
        let (disclosure, digest) = encoded_disclosure(&json!(["salt", "family_name", "Disclosed"]));
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "family_name": "Visible",
            "_sd_alg": "sha-256",
            "_sd": [digest],
        });

        let error = compact_verification_error(compact_presentation(&payload, &[disclosure]));
        match &error {
            Error::DuplicateKeyError(message) => {
                assert_eq!(message, super::DUPLICATE_DISCLOSED_CLAIM)
            }
            other => panic!("expected DuplicateKeyError, got {other:?}"),
        }
        assert!(!error.to_string().contains("family_name"));
    }

    #[test]
    fn two_disclosures_cannot_create_the_same_claim_name() {
        let (first, first_digest) = encoded_disclosure(&json!(["salt-a", "family_name", "First"]));
        let (second, second_digest) =
            encoded_disclosure(&json!(["salt-b", "family_name", "Second"]));
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "_sd": [first_digest, second_digest],
        });

        let error = compact_verification_error(compact_presentation(&payload, &[first, second]));
        match &error {
            Error::DuplicateKeyError(message) => {
                assert_eq!(message, super::DUPLICATE_DISCLOSED_CLAIM)
            }
            other => panic!("expected DuplicateKeyError, got {other:?}"),
        }
        assert!(!error.to_string().contains("family_name"));
    }

    #[test]
    fn non_string_digest_and_disclosed_name_keep_conversion_error_contract() {
        let non_string_digest_payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "_sd": [42],
        });
        let error =
            compact_verification_error(compact_presentation(&non_string_digest_payload, &[]));
        assert!(matches!(&error, Error::ConversionError(target) if target == "str"));
        assert_eq!(error.to_string(), "conversion error: Cannot convert to str");

        let (disclosure, digest) = encoded_disclosure(&json!(["salt", 42, "not-a-named-claim"]));
        let non_string_name_payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "_sd": [digest],
        });
        let error = compact_verification_error(compact_presentation(
            &non_string_name_payload,
            &[disclosure],
        ));
        assert!(matches!(&error, Error::ConversionError(target) if target == "str"));
        assert_eq!(error.to_string(), "conversion error: Cannot convert to str");
    }

    #[test]
    fn scalar_and_object_disclosures_keep_invalid_array_error_contract() {
        for decoded in [json!("scalar disclosure"), json!({"salt": "value"})] {
            let (disclosure, digest) = encoded_disclosure(&decoded);
            let payload = json!({
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "_sd_alg": "sha-256",
                "_sd": [digest],
            });

            let error = compact_verification_error(compact_presentation(&payload, &[disclosure]));
            match &error {
                Error::InvalidArrayDisclosureObject(actual) => {
                    assert_eq!(actual, super::INVALID_OBJECT_DISCLOSURE_TYPE)
                }
                other => panic!("expected InvalidArrayDisclosureObject, got {other:?}"),
            }
            assert_eq!(
                error.to_string(),
                format!(
                    "invalid array disclosure: {}",
                    super::INVALID_OBJECT_DISCLOSURE_TYPE
                )
            );
        }
    }

    #[test]
    fn missing_object_and_array_disclosures_are_accepted_as_decoys() {
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "_sd": ["missing-object-disclosure"],
            "items": [{"...": "missing-array-disclosure"}],
        });

        let verifier = verify_compact(compact_presentation(&payload, &[])).unwrap();
        assert_eq!(
            verifier.verified_claims,
            json!({
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "items": [],
            })
        );
    }

    #[test]
    fn verifier_error_precedence_is_preprocessing_then_signature_then_reconstruction() {
        let (scalar_disclosure, digest) = encoded_disclosure(&json!("not-an-array"));
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "_sd": [digest],
        });
        let valid = compact_presentation(&payload, std::slice::from_ref(&scalar_disclosure));
        let invalid_signature = corrupt_compact_signature(&valid);

        let malformed_disclosure = "%".to_string();
        let malformed_and_invalid_signature = corrupt_compact_signature(&compact_presentation(
            &payload,
            &[malformed_disclosure.clone(), scalar_disclosure],
        ));
        let preprocessing_error = compact_verification_error(malformed_and_invalid_signature);
        match &preprocessing_error {
            Error::InvalidDisclosure(message) => assert!(
                message.starts_with("Error decoding disclosure:")
                    && !message.contains(&malformed_disclosure),
                "unexpected preprocessing message: {message}"
            ),
            other => panic!("expected InvalidDisclosure, got {other:?}"),
        }
        assert!(
            preprocessing_error
                .to_string()
                .starts_with("invalid disclosure: Error decoding disclosure:")
                && !preprocessing_error
                    .to_string()
                    .contains(&malformed_disclosure),
            "unexpected preprocessing error: {preprocessing_error}"
        );

        let signature_error = compact_verification_error(invalid_signature);
        match &signature_error {
            Error::DeserializationError(message) => assert!(
                message.starts_with("Cannot decode jwt:"),
                "unexpected signature message: {message}"
            ),
            other => panic!("expected DeserializationError, got {other:?}"),
        }
        assert!(
            signature_error
                .to_string()
                .starts_with("invalid input: Cannot decode jwt:"),
            "unexpected signature error: {signature_error}"
        );

        let reconstruction_error = compact_verification_error(valid);
        match &reconstruction_error {
            Error::InvalidArrayDisclosureObject(actual) => {
                assert_eq!(actual, super::INVALID_OBJECT_DISCLOSURE_TYPE)
            }
            other => panic!("expected InvalidArrayDisclosureObject, got {other:?}"),
        }
        assert_eq!(
            reconstruction_error.to_string(),
            format!(
                "invalid array disclosure: {}",
                super::INVALID_OBJECT_DISCLOSURE_TYPE
            )
        );
    }

    #[test]
    fn disclosure_presentation_order_does_not_change_reconstructed_claims_without_kb_jwt() {
        let (family_name, family_name_digest) =
            encoded_disclosure(&json!(["salt-a", "family_name", "Miller"]));
        let (given_name, given_name_digest) =
            encoded_disclosure(&json!(["salt-b", "given_name", "Erika"]));
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "_sd": [family_name_digest, given_name_digest],
        });

        let forward = verify_compact(compact_presentation(
            &payload,
            &[family_name.clone(), given_name.clone()],
        ))
        .unwrap();
        let reversed =
            verify_compact(compact_presentation(&payload, &[given_name, family_name])).unwrap();

        assert_eq!(forward.verified_claims, reversed.verified_claims);
        assert_eq!(
            forward.verified_claims,
            json!({
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "family_name": "Miller",
                "given_name": "Erika",
            })
        );
    }

    #[test]
    fn unreferenced_disclosure_error_follows_presentation_order() {
        let (first, first_digest) = encoded_disclosure(&json!(["salt-a", "first_claim", "first"]));
        let (second, second_digest) =
            encoded_disclosure(&json!(["salt-b", "second_claim", "second"]));
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
        });

        for (disclosures, untrusted_digest) in [
            (vec![first.clone(), second.clone()], first_digest.clone()),
            (vec![second, first], second_digest),
        ] {
            let error = compact_verification_error(compact_presentation(&payload, &disclosures));

            match &error {
                Error::InvalidDisclosure(message) => {
                    assert_eq!(message, super::UNREFERENCED_DISCLOSURE)
                }
                other => panic!("expected InvalidDisclosure, got {other:?}"),
            }
            assert!(!error.to_string().contains(&untrusted_digest));
        }
    }

    #[test]
    fn inconsistent_preprocessed_digest_cardinality_fails_closed_without_item_data() {
        let (disclosure, digest) = encoded_disclosure(&json!(["salt", "family_name", "Miller"]));
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "_sd": [digest],
        });
        let presentation = compact_presentation(&payload, std::slice::from_ref(&disclosure));

        for retained_digests in [Vec::new(), vec![digest.clone(), digest.clone()]] {
            let mut verifier = verify_compact(presentation.clone()).unwrap();
            verifier.sd_jwt_engine.ordered_disclosure_digests = retained_digests;

            let error = verifier.extract_sd_claims().unwrap_err();
            match &error {
                Error::InvalidState(message) => {
                    assert_eq!(message, super::DISCLOSURE_PREPROCESSING_STATE_FAILURE)
                }
                other => panic!("expected InvalidState, got {other:?}"),
            }
            assert_eq!(
                error.to_string(),
                "invalid state: Disclosure preprocessing state is inconsistent"
            );
            assert!(!error.to_string().contains(&digest));
            assert!(!error.to_string().contains(&disclosure));
        }
    }

    #[test]
    fn reconstruction_error_precedes_unreferenced_disclosure_selection() {
        let (unreferenced, _) = encoded_disclosure(&json!(["extra-salt", "extra_claim", "extra"]));
        let (scalar, scalar_digest) = encoded_disclosure(&json!("not-an-array"));
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "_sd": [scalar_digest],
        });

        let error =
            compact_verification_error(compact_presentation(&payload, &[unreferenced, scalar]));
        match &error {
            Error::InvalidArrayDisclosureObject(actual) => {
                assert_eq!(actual, super::INVALID_OBJECT_DISCLOSURE_TYPE)
            }
            other => panic!("expected InvalidArrayDisclosureObject, got {other:?}"),
        }
        assert_eq!(
            error.to_string(),
            format!(
                "invalid array disclosure: {}",
                super::INVALID_OBJECT_DISCLOSURE_TYPE
            )
        );
    }

    #[rstest]
    #[case::object_chain(RecursiveFixtureKind::Object)]
    #[case::array_chain(RecursiveFixtureKind::Array)]
    #[case::alternating_chain(RecursiveFixtureKind::Alternating)]
    fn cumulative_processed_depth_accepts_127_and_128_but_rejects_129(
        #[case] fixture_kind: RecursiveFixtureKind,
    ) {
        let limit = super::MAX_PROCESSED_SD_JWT_DEPTH;

        for accepted_depth in [limit - 1, limit] {
            let fixture = recursive_disclosure_fixture(accepted_depth, fixture_kind);
            verify_compact(fixture.presentation()).unwrap_or_else(|error| {
                panic!("{fixture_kind:?} fixture at depth {accepted_depth} was rejected: {error}")
            });
        }

        let fixture = recursive_disclosure_fixture(limit + 1, fixture_kind);
        assert_processed_depth_limit(compact_verification_error(fixture.presentation()));
    }

    #[test]
    fn cumulative_processed_depth_does_not_reject_wide_fan_out() {
        const DISCLOSURE_COUNT: usize = 512;
        let mut disclosures = Vec::with_capacity(DISCLOSURE_COUNT);
        let mut digests = Vec::with_capacity(DISCLOSURE_COUNT);
        for ordinal in 0..DISCLOSURE_COUNT {
            let (disclosure, digest) = encoded_disclosure(&json!([
                format!("wide-salt-{ordinal}"),
                format!("wide-claim-{ordinal}"),
                ordinal,
            ]));
            disclosures.push(disclosure);
            digests.push(digest);
        }
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": "sha-256",
            "_sd": digests,
        });

        let verifier = verify_compact(compact_presentation(&payload, &disclosures)).unwrap();
        let claims = verifier.verified_claims.as_object().unwrap();
        assert_eq!(claims.len(), DISCLOSURE_COUNT + 2);
        assert_eq!(claims["wide-claim-0"], 0);
        assert_eq!(
            claims[&format!("wide-claim-{}", DISCLOSURE_COUNT - 1)],
            DISCLOSURE_COUNT - 1
        );
    }

    #[test]
    fn individually_shallow_disclosures_cannot_compose_an_over_limit_value() {
        let fixture = recursive_disclosure_fixture(
            super::MAX_PROCESSED_SD_JWT_DEPTH + 1,
            RecursiveFixtureKind::Alternating,
        );

        for disclosure in &fixture.disclosures {
            let decoded = base64url_decode(disclosure).unwrap();
            let value: Value = serde_json::from_slice(&decoded).unwrap();
            assert!(
                composite_depth(&value) <= 3,
                "fixture Disclosure was not independently shallow: {value}"
            );
        }

        assert_processed_depth_limit(compact_verification_error(fixture.presentation()));
    }

    #[test]
    fn preprocessing_and_signature_errors_precede_processed_depth_limit() {
        let fixture = recursive_disclosure_fixture(
            super::MAX_PROCESSED_SD_JWT_DEPTH + 1,
            RecursiveFixtureKind::Object,
        );
        let invalid_signature = corrupt_compact_signature(&fixture.presentation());
        let signature_error = compact_verification_error(invalid_signature.clone());
        assert!(
            matches!(&signature_error, Error::DeserializationError(message) if message.starts_with("Cannot decode jwt:")),
            "expected signature error, got {signature_error:?}"
        );

        let (signed, disclosures) = invalid_signature
            .split_once(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .unwrap();
        let separator = COMBINED_SERIALIZATION_FORMAT_SEPARATOR;
        let malformed_and_invalid_signature =
            format!("{signed}{separator}%{separator}{disclosures}");
        let preprocessing_error = compact_verification_error(malformed_and_invalid_signature);
        assert!(
            matches!(&preprocessing_error, Error::InvalidDisclosure(message) if message.starts_with("Error decoding disclosure:") && !message.contains('%')),
            "expected preprocessing error, got {preprocessing_error:?}"
        );
    }

    #[test]
    fn current_reconstruction_errors_precede_processed_depth_limit() {
        let over_limit = super::MAX_PROCESSED_SD_JWT_DEPTH + 1;

        let mut duplicate_fixture =
            recursive_disclosure_fixture(over_limit, RecursiveFixtureKind::Object);
        let root_digest = duplicate_fixture.payload["_sd"][0].clone();
        duplicate_fixture.payload["_sd"] = json!([
            "repeated-decoy-before-recursion",
            "repeated-decoy-before-recursion",
            root_digest,
        ]);
        let duplicate_error = compact_verification_error(duplicate_fixture.presentation());
        assert!(
            matches!(&duplicate_error, Error::DuplicateDigestError(message) if message == super::DUPLICATE_DISCLOSURE_DIGEST),
            "expected duplicate digest error, got {duplicate_error:?}"
        );

        let mut collision_fixture =
            recursive_disclosure_fixture(over_limit, RecursiveFixtureKind::Object);
        collision_fixture.payload["recursive-root"] = json!("visible");
        let collision_error = compact_verification_error(collision_fixture.presentation());
        assert!(
            matches!(&collision_error, Error::DuplicateKeyError(message) if message == super::DUPLICATE_DISCLOSED_CLAIM),
            "expected duplicate key error, got {collision_error:?}"
        );

        let mut malformed_fixture =
            recursive_disclosure_fixture(over_limit, RecursiveFixtureKind::Object);
        let encoded_root = malformed_fixture.disclosures.pop().unwrap();
        let decoded_root = base64url_decode(&encoded_root).unwrap();
        let mut malformed_root: Value = serde_json::from_slice(&decoded_root).unwrap();
        malformed_root.as_array_mut().unwrap().push(json!("extra"));
        let (malformed_root, malformed_root_digest) = encoded_disclosure(&malformed_root);
        malformed_fixture.payload["_sd"] = json!([malformed_root_digest]);
        malformed_fixture.disclosures.push(malformed_root);
        let malformed_error = compact_verification_error(malformed_fixture.presentation());
        assert!(
            matches!(&malformed_error, Error::InvalidDisclosure(message) if message.starts_with("Object-property Disclosure must be a 3-element array")),
            "expected malformed Disclosure error, got {malformed_error:?}"
        );
    }

    #[test]
    fn structural_disclosure_errors_do_not_echo_decoded_material() {
        const SENTINEL: &str = "decoded-private-disclosure-sentinel";
        let malformed_values = [
            (json!({ "secret": SENTINEL }), false),
            (json!([SENTINEL, "name", "value", "extra"]), false),
            (json!({ "secret": SENTINEL }), true),
            (json!([SENTINEL, "value", "extra"]), true),
        ];

        for (malformed, array_element) in malformed_values {
            let (encoded, digest) = encoded_disclosure(&malformed);
            let payload = if array_element {
                json!({
                    "iss": "https://example.com/issuer",
                    "iat": 1683000000,
                    "items": [{ "...": digest }],
                })
            } else {
                json!({
                    "iss": "https://example.com/issuer",
                    "iat": 1683000000,
                    "_sd_alg": "sha-256",
                    "_sd": [digest],
                })
            };
            let presentation = compact_presentation(&payload, &[encoded]);
            let error = compact_verification_error(presentation);
            assert!(
                matches!(
                    &error,
                    Error::InvalidDisclosure(_) | Error::InvalidArrayDisclosureObject(_)
                ),
                "expected structural Disclosure error, got {error:?}"
            );
            assert!(
                !error.to_string().contains(SENTINEL),
                "structural error exposed decoded Disclosure material: {error}"
            );
        }
    }

    #[test]
    fn digest_algorithm_error_does_not_echo_untrusted_value() {
        const SENTINEL: &str = "untrusted-digest-algorithm-sentinel";
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd_alg": SENTINEL,
        });
        let error = compact_verification_error(compact_presentation(&payload, &[]));

        assert!(matches!(
            &error,
            Error::DeserializationError(message) if message == super::INVALID_DIGEST_ALGORITHM
        ));
        assert!(!error.to_string().contains(SENTINEL));
    }

    #[test]
    fn processed_depth_limit_precedes_later_duplicate_and_unreferenced_errors() {
        let mut fixture = recursive_disclosure_fixture(
            super::MAX_PROCESSED_SD_JWT_DEPTH + 1,
            RecursiveFixtureKind::Alternating,
        );
        let root_digest = fixture.payload["_sd"][0].clone();
        fixture.payload["_sd"] = json!([
            root_digest,
            "repeated-decoy-after-recursion",
            "repeated-decoy-after-recursion",
        ]);
        let (unreferenced, _) =
            encoded_disclosure(&json!(["unreferenced-salt", "unreferenced", true]));
        fixture.disclosures.push(unreferenced);

        assert_processed_depth_limit(compact_verification_error(fixture.presentation()));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn processed_depth_limit_prevents_stack_abort_in_isolated_child() {
        const CHILD_ENV: &str = "SD_JWT_RS_DEPTH_LIMIT_CHILD";
        const CHILD_SENTINEL: &str = "SD_JWT_RS_DEPTH_LIMIT_CHILD_OK";
        const TEST_NAME: &str =
            "verifier::tests::processed_depth_limit_prevents_stack_abort_in_isolated_child";

        if std::env::var_os(CHILD_ENV).is_some() {
            let child = std::thread::Builder::new()
                .name("sd-jwt-depth-limit-child".to_owned())
                .stack_size(1024 * 1024)
                .spawn(|| {
                    let fixture = recursive_disclosure_fixture(
                        super::MAX_PROCESSED_SD_JWT_DEPTH + 4096,
                        RecursiveFixtureKind::Alternating,
                    );
                    assert_processed_depth_limit(compact_verification_error(
                        fixture.presentation(),
                    ));
                })
                .unwrap();
            assert!(child.join().is_ok(), "depth-limit child thread panicked");
            println!("{CHILD_SENTINEL}");
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "isolated depth-limit child failed with {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
        assert!(
            stdout.contains(CHILD_SENTINEL),
            "isolated child did not execute the intended test\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn reject_sd_jwt_with_nested_sd_alg() {
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "_sd_alg": "sha-256",
            "address": { "_sd_alg": "sha-256" }
        });
        let header = Header::new(Algorithm::ES256);
        let signed = jsonwebtoken::encode(&header, &payload, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );

        assert!(result.is_err(), "verifier accepted a nested `_sd_alg`");
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains("only allowed at the top level"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn verify_full_presentation() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, None)
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();
        let presentation = SDJWTHolder::new(
            sd_jwt.clone(),
            SDJWTSerializationFormat::Compact,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
        )
        .unwrap()
        .create_presentation_with_local_key(
            user_claims.as_object().unwrap().clone(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap()
        .verified_claims;
        assert_eq!(user_claims, verified_claims);
    }

    #[test]
    fn verify_noclaim_presentation() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, None)
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let presentation =
            SDJWTHolder::new_unverified(sd_jwt.clone(), SDJWTSerializationFormat::Compact)
                .unwrap()
                .create_presentation_with_local_key(
                    user_claims.as_object().unwrap().clone(),
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();
        assert_eq!(sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap()
        .verified_claims;
        assert_eq!(user_claims, verified_claims);
    }

    #[test]
    fn verify_arrayed_presentation() {
        let user_claims = json!(
            {
              "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
              "name": "Bois",
              "iss": "https://example.com/issuer",
              "iat": 1683000000,
              "exp": 1883000000,
              "addresses": [
                {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
                },
                {
                "street_address": "456 Main St",
                "locality": "Anytown",
                "region": "NY",
                "country": "US"
                }
              ],
              "nationalities": [
                "US",
                "CA"
              ]
            }
        );
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "$.name",
            "$.addresses[1]",
            "$.addresses[1].country",
            "$.nationalities[0]",
        ]);
        let sd_jwt = SDJWTIssuer::new(issuer_key, None)
            .issue_sd_jwt(
                user_claims.clone(),
                strategy,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let mut claims_to_disclose = user_claims.clone();
        claims_to_disclose["addresses"] = Value::Array(vec![Value::Bool(true), Value::Bool(true)]);
        claims_to_disclose["nationalities"] =
            Value::Array(vec![Value::Bool(true), Value::Bool(true)]);
        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation_with_local_key(
                claims_to_disclose.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let verified_claims = SDJWTVerifier::new(
            presentation.clone(),
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap()
        .verified_claims;

        let expected_verified_claims = json!(
            {
                "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
                "addresses": [
                    {
                        "street_address": "Schulstr. 12",
                        "locality": "Schulpforta",
                        "region": "Sachsen-Anhalt",
                        "country": "DE",
                    },
                    {
                        "street_address": "456 Main St",
                        "locality": "Anytown",
                        "region": "NY",
                    },
                ],
                "nationalities": [
                    "US",
                    "CA",
                ],
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "exp": 1883000000,
                "name": "Bois"
            }
        );

        assert_eq!(verified_claims, expected_verified_claims);
    }

    #[test]
    fn verify_arrayed_no_sd_presentation() {
        let user_claims = json!(
            {
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "exp": 1883000000,
                "array_with_recursive_sd": [
                    "boring",
                    {
                        "foo": "bar",
                        "baz": {
                            "qux": "quux"
                        }
                    },
                    ["foo", "bar"]
                ],
                "test2": ["foo", "bar"]
            }
        );
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "$.array_with_recursive_sd[1]",
            "$.array_with_recursive_sd[1].baz",
            "$.array_with_recursive_sd[2][0]",
            "$.array_with_recursive_sd[2][1]",
            "$.test2[0]",
            "$.test2[1]",
        ]);
        let sd_jwt = SDJWTIssuer::new(issuer_key, None)
            .issue_sd_jwt(
                user_claims.clone(),
                strategy,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let claims_to_disclose = json!({});

        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation_with_local_key(
                claims_to_disclose.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let verified_claims = SDJWTVerifier::new(
            presentation.clone(),
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap()
        .verified_claims;

        let expected_verified_claims = json!(
            {
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "exp": 1883000000,
                "array_with_recursive_sd":  [
                    "boring",
                    [],
                ],
                "test2": [],
            }
        );

        assert_eq!(verified_claims, expected_verified_claims);
    }

    #[test]
    fn verify_full_presentation_to_allow_other_algorithms() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });
        let private_issuer_bytes = PRIVATE_ISSUER_ED25519_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ed_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, Some("EdDSA".to_string()))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
            )
            .unwrap();

        let presentation = SDJWTHolder::new(
            sd_jwt.clone(),
            SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
            Box::new(|_, _| {
                DecodingKey::from_ed_pem(PUBLIC_ISSUER_ED25519_PEM.as_bytes()).unwrap()
            }),
        )
        .unwrap()
        .create_presentation_with_local_key(
            user_claims.as_object().unwrap().clone(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_ED25519_PEM.as_bytes();
                DecodingKey::from_ed_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
        )
        .unwrap()
        .verified_claims;
        assert_eq!(user_claims, verified_claims);
    }
    #[test]
    fn verify_presentation_when_sd_jwt_uses_es256_and_key_binding_uses_eddsa() {
        let user_claims = json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "exp": 1883000000,
            "iat": 1683000000,
            "iss": "https://example.com/issuer",
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",

        });

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();

        let mut issuer = SDJWTIssuer::new(issuer_key, Some("ES256".to_string()));

        let sd_jwt = issuer
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
            )
            .unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();

        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let mut holder =
            SDJWTHolder::new_unverified(sd_jwt.clone(), SDJWTSerializationFormat::FlattenedJson)
                .unwrap(); // Changed to Flattened Json format
        let presentation = holder
            .create_presentation_with_local_key(
                user_claims.as_object().unwrap().clone(),
                nonce.clone(),
                aud.clone(),
                Some(holder_key),
                Some("EdDSA".to_string()),
            )
            .unwrap();
        let verified_claims = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            aud.clone(),
            nonce.clone(),
            SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
        )
        .unwrap()
        .verified_claims;

        let claims_to_check = json!({
            "iss": user_claims["iss"].clone(),
            "iat": user_claims["iat"].clone(),
            "exp": user_claims["exp"].clone(),
            "cnf": {
                "jwk": serde_json::from_str::<Value>(HOLDER_JWK_KEY_ED25519).unwrap(),
            },
            "sub": user_claims["sub"].clone(),
            "address": user_claims["address"].clone(),
        });

        assert_eq!(claims_to_check, verified_claims);
    }

    #[rstest]
    #[case::flattened(SDJWTSerializationFormat::FlattenedJson)]
    #[case::general(SDJWTSerializationFormat::GeneralJson)]
    #[case::compact(SDJWTSerializationFormat::Compact)]
    fn reject_tampered_presentation_with_injected_disclosure(
        #[case] format: SDJWTSerializationFormat,
    ) {
        let user_claims = json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "exp": 1883000000,
            "iat": 1683000000,
            "iss": "https://example.com/issuer",
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        });

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();

        let sd_jwt = SDJWTIssuer::new(issuer_key, Some("ES256".to_string()))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                format.clone(),
            )
            .unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();
        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let presentation = SDJWTHolder::new_unverified(sd_jwt, format.clone())
            .unwrap()
            .create_presentation_with_local_key(
                user_claims.as_object().unwrap().clone(),
                nonce.clone(),
                aud.clone(),
                Some(holder_key),
                Some("EdDSA".to_string()),
            )
            .unwrap();

        // Tamper: inject a syntactically-valid extra disclosure into the presentation.
        // The KB-JWT's sd_hash was computed by the holder over the original disclosure
        // list, so the verifier MUST detect the mismatch. Where the disclosure goes
        // differs by format: a `~`-separated segment before the KB-JWT (Compact §4),
        // a top-level `header` member (Flattened §8.2), or the first signature's
        // header (General §8.3).
        let injected_disclosure =
            base64url_encode(br#"["injectedsalt", "injected_claim", "value"]"#);
        let tampered = match format {
            SDJWTSerializationFormat::FlattenedJson => {
                let mut json: SDJWTFlattenedJson = serde_json::from_str(&presentation).unwrap();
                json.header.disclosures.push(injected_disclosure);
                serde_json::to_string(&json).unwrap()
            }
            SDJWTSerializationFormat::GeneralJson => {
                let mut json: SDJWTGeneralJson = serde_json::from_str(&presentation).unwrap();
                json.signatures[0]
                    .header
                    .disclosures
                    .push(injected_disclosure);
                serde_json::to_string(&json).unwrap()
            }
            SDJWTSerializationFormat::Compact => {
                // presentation = "<jwt>~<disclosures…>~<kb_jwt>"; splice the extra
                // disclosure in just before the trailing KB-JWT segment.
                let mut parts: Vec<&str> = presentation
                    .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
                    .collect();
                parts.insert(parts.len() - 1, &injected_disclosure);
                parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            }
        };

        let result = SDJWTVerifier::new(
            tampered,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            aud,
            nonce,
            format.clone(),
        );

        assert!(
            result.is_err(),
            "Verifier accepted {format:?} presentation with tampered disclosure list",
        );
    }

    #[test]
    fn reject_general_json_with_multiple_signatures() {
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        });

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();

        let sd_jwt = SDJWTIssuer::new(issuer_key, Some("ES256".to_string()))
            .issue_sd_jwt(
                user_claims,
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::GeneralJson,
            )
            .unwrap();

        let mut json: SDJWTGeneralJson = serde_json::from_str(&sd_jwt).unwrap();
        let duplicated = json.signatures[0].clone();
        json.signatures.push(duplicated);
        let tampered = serde_json::to_string(&json).unwrap();

        let result = SDJWTVerifier::new(
            tampered,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::GeneralJson,
        );

        assert!(
            result.is_err(),
            "Verifier accepted a General JSON SD-JWT with multiple signatures",
        );
    }

    #[test]
    fn reject_kb_jwt_missing_iat_claim() {
        let user_claims = json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "exp": 1883000000,
            "iat": 1683000000,
            "iss": "https://example.com/issuer",
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        });

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, Some("ES256".to_string()))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                SDJWTSerializationFormat::FlattenedJson,
            )
            .unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();
        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let presentation =
            SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::FlattenedJson)
                .unwrap()
                .create_presentation_with_local_key(
                    user_claims.as_object().unwrap().clone(),
                    nonce.clone(),
                    aud.clone(),
                    Some(holder_key),
                    Some("EdDSA".to_string()),
                )
                .unwrap();

        // Tamper: re-sign the KB-JWT with the `iat` claim stripped from the
        // payload. The KB-JWT remains validly signed by the holder key, so
        // signature verification will pass — but the spec requires `iat` to
        // be present, and the verifier must reject this presentation.
        let mut json: SDJWTFlattenedJson = serde_json::from_str(&presentation).unwrap();
        let original_kb_jwt = json.header.kb_jwt.clone().unwrap();
        let kb_parts: Vec<&str> = original_kb_jwt.split('.').collect();
        let payload_bytes = base64url_decode(kb_parts[1]).unwrap();
        let mut kb_payload: Map<String, Value> = serde_json::from_slice(&payload_bytes).unwrap();
        kb_payload.remove("iat");

        let resign_key = EncodingKey::from_ed_pem(HOLDER_KEY_ED25519.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(crate::KB_JWT_TYP_HEADER.to_string());
        let tampered_kb_jwt = jsonwebtoken::encode(&header, &kb_payload, &resign_key).unwrap();

        json.header.kb_jwt = Some(tampered_kb_jwt);
        let tampered_presentation = serde_json::to_string(&json).unwrap();

        let result = SDJWTVerifier::new(
            tampered_presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            aud,
            nonce,
            SDJWTSerializationFormat::FlattenedJson,
        );

        assert!(
            result.is_err(),
            "Verifier accepted KB-JWT presentation missing required `iat` claim",
        );
    }

    #[test]
    fn reject_sd_jwt_with_future_nbf() {
        // An SD-JWT whose `nbf` is in the future is not yet valid.
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "nbf": 1883000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &payload, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        match result {
            Ok(_) => panic!("verifier accepted a presentation with a future `nbf`"),
            Err(err) => assert!(
                err.to_string().contains("ImmatureSignature"),
                "expected an immature-signature failure, got: {err}"
            ),
        }
    }

    #[test]
    fn verify_presentation_with_past_nbf() {
        // A present `nbf` already in the past must not block verification.
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "nbf": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &user_claims, &issuer_key)
                .unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(
            result.is_ok(),
            "verifier rejected an SD-JWT with a past `nbf`"
        );
    }

    #[test]
    fn reject_presentation_with_unreferenced_disclosure() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, None)
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();
        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation_with_local_key(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Append a syntactically-valid but unreferenced disclosure. The
        // legitimate disclosures still hash and unpack normally; only the
        // injected disclosure is not referenced by any digest in the
        // Issuer-signed JWT, so the verifier must reject per draft-07 §8.1.
        let injected = base64url_encode(br#"["unreferencedsalt", "unreferenced_claim", "value"]"#);
        let presentation = presentation.trim_end_matches(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
        let tampered = format!(
            "{presentation}{COMBINED_SERIALIZATION_FORMAT_SEPARATOR}{injected}{COMBINED_SERIALIZATION_FORMAT_SEPARATOR}"
        );

        let result = SDJWTVerifier::new(
            tampered,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );

        assert!(
            result.is_err(),
            "Verifier accepted presentation with unreferenced disclosure",
        );
    }

    #[test]
    fn verify_presentation_without_exp() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, None)
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation_with_local_key(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let result = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(result.is_ok(), "verifier rejected `exp`-less SD-JWT");
    }

    #[test]
    fn reject_disclosure_with_reserved_claim_name() {
        use crate::utils::base64_hash;
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        for reserved in ["_sd", "..."] {
            // A well-formed (3-element) Disclosure that discloses a claim named
            // `_sd` or `...`; §7.1 requires the Verifier to reject it.
            let disclosure =
                base64url_encode(format!(r#"["salt", "{reserved}", "value"]"#).as_bytes());
            let digest = base64_hash(disclosure.as_bytes());
            let payload = json!({
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "_sd": [digest],
                "_sd_alg": "sha-256",
            });
            let signed =
                jsonwebtoken::encode(&Header::new(Algorithm::ES256), &payload, &issuer_key)
                    .unwrap();
            let sd_jwt = format!("{signed}~{disclosure}~");

            let result = SDJWTVerifier::new(
                sd_jwt,
                Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
                None,
                None,
                SDJWTSerializationFormat::Compact,
            );
            let error = match result {
                Ok(_) => {
                    panic!("verifier accepted a Disclosure with reserved claim name `{reserved}`")
                }
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                format!(
                    "invalid disclosure: {}",
                    super::RESERVED_DISCLOSURE_CLAIM_NAME
                )
            );
            assert!(!error.to_string().contains(reserved));
        }
    }

    #[test]
    fn reject_presentation_with_expired_exp() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1683000300,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, None)
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        match result {
            Ok(_) => panic!("verifier accepted a presentation with an expired `exp`"),
            Err(err) => assert!(
                err.to_string().contains("ExpiredSignature"),
                "expected an expiry failure, got: {err}"
            ),
        }
    }

    #[test]
    fn reject_object_property_disclosure_with_wrong_element_count() {
        use crate::utils::base64_hash;
        // A conforming object-property Disclosure is a 3-element array
        // [salt, claim name, claim value]. Craft a malformed 2-element one
        // and reference its digest from the signed `_sd` array.
        let malformed = base64url_encode(br#"["salt", "valuewithoutname"]"#);
        let digest = base64_hash(malformed.as_bytes());
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd": [digest],
            "_sd_alg": "sha-256",
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &payload, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~{malformed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(
            result.is_err(),
            "verifier accepted a malformed (non-3-element) object-property Disclosure",
        );
    }

    #[test]
    fn reject_array_element_disclosure_with_wrong_element_count() {
        use crate::utils::base64_hash;
        // A conforming array-element Disclosure is a 2-element array
        // [salt, value]. Craft a malformed 3-element one and reference it
        // via {"...": digest}.
        let malformed = base64url_encode(br#"["salt", "claimname", "value"]"#);
        let digest = base64_hash(malformed.as_bytes());
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "arr": [ { "...": digest } ],
            "_sd_alg": "sha-256",
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &payload, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~{malformed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(
            result.is_err(),
            "verifier accepted a malformed (non-2-element) array-element Disclosure",
        );
    }
}
