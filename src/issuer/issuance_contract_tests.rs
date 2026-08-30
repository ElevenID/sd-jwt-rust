// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(feature = "mock_salts"))]
use super::IssuanceRandomSource;
use super::{ClaimsForSelectiveDisclosureStrategy, LegacyIssuanceRandomSource, SDJWTIssuer};
use crate::utils::{base64_hash, base64url_decode, base64url_encode};
#[cfg(feature = "mock_salts")]
use crate::SD_LIST_PREFIX;
use crate::{SDJWTSerializationFormat, DEFAULT_DIGEST_ALG, SD_DIGESTS_KEY};
#[cfg(feature = "mock_salts")]
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::EncodingKey;
use rand::{Error as RandError, RngCore};
use serde_json::{json, Value};
use std::cell::Cell;
#[cfg(not(feature = "mock_salts"))]
use std::{collections::VecDeque, ops::Range};

const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
#[cfg(feature = "mock_salts")]
const HOLDER_JWK: &str = r#"{
    "kty": "EC",
    "crv": "P-256",
    "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
    "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
}"#;
#[cfg(feature = "mock_salts")]
const GOLDEN_COMPACT_WITH_HOLDER_KEY: &str = concat!(
    "eyJhbGciOiJFUzI1NiJ9",
    ".",
    "eyJfc2QiOlsiR0N3NE5LTndsRFo1N1dEZk51dDRsMzRTM0Z0NVN0d2hsX2k4UXFxUlRSRSIsIkpYT2FsNk80RnVzd0dhVFBsQ0hLX1dMVE02SEtxekZ6QURFXzNobUE5eVUiLCJtMUNya1ptVmZJZUpPWmpEUnI5QnNIdkt6U3czZXBjd1JfVWd4Q2FPc0lNIl0sIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZSIsImlhdCI6MSwiZXhwIjoyLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsInkiOiJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ",
    ".",
    "qpkWlTFsIJ7P8pbCZQhzZrh9egz0wHHWgVwPynC43xf02jH-0iS7LIl2EFE_imiNyiwVsckuqOZPvM4Lm7pt-w",
    "~",
    "WyJ0ZXN0LXNhbHQtMDAwMCIsICJuYW1lIiwgIkFsaWNlIl0",
    "~",
    "WyJ0ZXN0LXNhbHQtMDAwMSIsICJjaXR5IiwgIkRlbnZlciJd",
    "~",
    "WyJ0ZXN0LXNhbHQtMDAwMiIsICJhZGRyZXNzIiwgeyJfc2QiOiBbIk5nQzktb01qQWoyMm92YTNfampBMVhzd2h1a0pKbXlvSnM1eWczVjdEOG8iXX1d",
    "~",
    "WyJ0ZXN0LXNhbHQtMDAwMyIsICJhZG1pbiJd",
    "~",
    "WyJ0ZXN0LXNhbHQtMDAwNCIsICJyb2xlcyIsIFt7Ii4uLiI6ICJyc0NicGNhZGZ2VVJmTi1OLVIyVzlMMlRLSEFsNXNsSlIwUUdyalczWjJVIn1dXQ",
    "~",
);
#[cfg(not(feature = "mock_salts"))]
const GOLDEN_COMPACT_WITH_DECOYS: &str = concat!(
    "eyJhbGciOiJFUzI1NiJ9",
    ".",
    "eyJfc2QiOlsiM2pJWi15UzhxUDgzRU03S3hOY1o3dlIyQmg3c3RvRmlFMVdsZFhmV1BwYyIsIll2VGotY29DbVBILUhlbklYQVE1bXo2Z0Y0NVc2VlZvcVVWMGdnVnJkMlkiLCJ2dGdsbFJ1bG43ZGdOdDhZMkhFNXBQcDVkMGlCcndQUnZma0taTHV4OHhjIiwid0c1ODcwZW5vd2xrZVoyS2wtdUxfWC1xU3JiZ3Bka054dERtU3FuN1RrYyJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9",
    ".",
    "GcJ0HDlqMWPJZqNou1dT1cK8BkqF28NnUutqE370JWxbvLj4mvlcadIEI-BY6SwkeV1EX2bR7YXlfXsSW_bk4w",
    "~",
    "WyJFUkVSRVJFUkVSRVJFUkVSRVJFUkVRIiwgIm5hbWUiLCAiQWxpY2UiXQ",
    "~",
);
#[cfg(not(feature = "mock_salts"))]
const GOLDEN_NESTED_COMPACT_WITH_DECOYS: &str = concat!(
    "eyJhbGciOiJFUzI1NiJ9",
    ".",
    "eyJfc2QiOlsiLTlUZ3RRb1RsR3VybGxFNExJeXZtSWVDTll3ZjVrWU0wS19KRWJtbzFnbyIsIkZqX1hVOVVlLTZPNEw3d2wyVUVEUWtGakhwTHhDcTlMazdRZnBaMHpFOTAiLCJwaXRwREw0cUxtUlpnNmtoVmlGOG55OUV3bUQzbDREZkN1RFdJWU5QQVdvIiwicVB0cEpmSkh1OWVod18zdVdtM21rM1F1cmhMRGhSdEVsZW5IMlJwd0FiRSIsInJfZjJaSXZIUUkyNk9YT3pobEQybFRJVzhYM0RXV2ZYUDhJQTZydGZhQ00iLCJ6WEJKS0wtTmdpNTdYSUdsN0IybUxPOUowR2FkZ2RZMFAtZTlvLUYwd0tnIl0sIl9zZF9hbGciOiJzaGEtMjU2In0",
    ".",
    "5zlxqmX49L32pV1b1j4hyzMhYyp7F3gibglcjtBhfXtkgOfa7OeawFHKDK1TiUpiStePh9cGVYTu8gAXZoF8Mw",
    "~",
    "WyJNVEV4TVRFeE1URXhNVEV4TVRFeE1RIiwgImNpdHkiLCAiRGVudmVyIl0",
    "~",
    "WyJNakl5TWpJeU1qSXlNakl5TWpJeU1nIiwgInByb2ZpbGUiLCB7Il9zZCI6WyJncXhLeEpoUEYtMDl1MmhOQ3hkbGFZeEFFaUNpM1BNTHJZbGVHcHIxdDBrIiwiaWY1N3puQlNjOFpTaFB1blFXTzZkVGZWai1qN2ZrU05zRXZYMDZ0T3lfSSIsInZpUlY3OVpHa1FmTTVNcjByM1YzcVphRU1KWWN2Zm54T2hPZlNTX1lCTXciXX1d",
    "~",
    "WyJNek16TXpNek16TXpNek16TXpNek13IiwgImFkbWluIl0",
    "~",
    "WyJORFEwTkRRME5EUTBORFEwTkRRME5BIiwgInJvbGVzIiwgW3siLi4uIjoiZTVaVnp5dzFhT1hSZG4tQWg4Qkl6WnFvZnpLZ2h2R2lNZFlHdXo1QURqdyJ9XV0",
    "~",
);

fn new_issuer() -> SDJWTIssuer {
    SDJWTIssuer::new(
        EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes())
            .expect("test issuer key must be valid"),
        None,
    )
}

#[cfg(feature = "mock_salts")]
fn expected_disclosure(decoded: &str) -> (String, String) {
    let encoded = base64url_encode(decoded.as_bytes());
    let digest = base64_hash(encoded.as_bytes());
    (encoded, digest)
}

fn decoded_jwt_payload(signed_jwt: &str) -> String {
    let payload = signed_jwt
        .split('.')
        .nth(1)
        .expect("signed JWT must contain a payload segment");
    String::from_utf8(base64url_decode(payload).expect("payload must be Base64url"))
        .expect("payload must be UTF-8 JSON")
}

fn nested_claims() -> Value {
    json!({
        "iss": "https://issuer.example",
        "iat": 1,
        "exp": 2,
        "name": "Alice",
        "address": { "city": "Denver" },
        "roles": ["admin"]
    })
}

#[cfg(not(feature = "mock_salts"))]
#[derive(Debug, Eq, PartialEq)]
enum RandomCall {
    DisclosureSalt,
    DecoyCount(Range<u32>),
    DecoySalt,
}

#[derive(Debug, Eq, PartialEq)]
enum RawRandomCall {
    FillBytes(usize),
    NextU32,
}

#[derive(Default)]
struct InstrumentedIssuanceRng {
    calls: Vec<RawRandomCall>,
    salt_ordinal: u8,
}

impl RngCore for InstrumentedIssuanceRng {
    fn next_u32(&mut self) -> u32 {
        self.calls.push(RawRandomCall::NextU32);
        0x8000_0000
    }

    fn next_u64(&mut self) -> u64 {
        panic!("u32 decoy-count sampling must not request a u64")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.calls.push(RawRandomCall::FillBytes(dest.len()));
        dest.fill(self.salt_ordinal);
        self.salt_ordinal = self.salt_ordinal.wrapping_add(1);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

thread_local! {
    static RNG_INITIALIZATION_COUNT: Cell<usize> = const { Cell::new(0) };
}

fn initialize_instrumented_rng() -> InstrumentedIssuanceRng {
    RNG_INITIALIZATION_COUNT.with(|count| count.set(count.get() + 1));
    InstrumentedIssuanceRng::default()
}

fn counted_random_source() -> LegacyIssuanceRandomSource<InstrumentedIssuanceRng> {
    RNG_INITIALIZATION_COUNT.with(|count| count.set(0));
    LegacyIssuanceRandomSource {
        rng: None,
        initialize: initialize_instrumented_rng,
    }
}

fn rng_initialization_count() -> usize {
    RNG_INITIALIZATION_COUNT.with(Cell::get)
}

#[cfg(not(feature = "mock_salts"))]
struct FixedIssuanceRandomSource {
    disclosure_salts: VecDeque<String>,
    decoy_counts: VecDeque<u32>,
    decoy_salts: VecDeque<String>,
    calls: Vec<RandomCall>,
}

#[cfg(not(feature = "mock_salts"))]
impl FixedIssuanceRandomSource {
    fn decoy_fixture() -> Self {
        Self {
            disclosure_salts: [base64url_encode(&[0x11; 16])].into_iter().collect(),
            decoy_counts: [3].into_iter().collect(),
            decoy_salts: [
                base64url_encode(&[0x21; 16]),
                base64url_encode(&[0x22; 16]),
                base64url_encode(&[0x23; 16]),
            ]
            .into_iter()
            .collect(),
            calls: Vec::new(),
        }
    }

    fn nested_decoy_fixture() -> Self {
        Self {
            disclosure_salts: [0x31, 0x32, 0x33, 0x34]
                .into_iter()
                .map(|byte| base64url_encode(&[byte; 16]))
                .collect(),
            decoy_counts: [2, 4].into_iter().collect(),
            decoy_salts: [0x41, 0x42, 0x43, 0x44, 0x45, 0x46]
                .into_iter()
                .map(|byte| base64url_encode(&[byte; 16]))
                .collect(),
            calls: Vec::new(),
        }
    }

    fn assert_exhausted(&self) {
        assert!(self.disclosure_salts.is_empty());
        assert!(self.decoy_counts.is_empty());
        assert!(self.decoy_salts.is_empty());
    }
}

#[cfg(not(feature = "mock_salts"))]
impl IssuanceRandomSource for FixedIssuanceRandomSource {
    fn disclosure_salt(&mut self) -> String {
        self.calls.push(RandomCall::DisclosureSalt);
        self.disclosure_salts
            .pop_front()
            .expect("fixed disclosure-salt tape must not be exhausted")
    }

    fn decoy_count(&mut self, range: Range<u32>) -> u32 {
        self.calls.push(RandomCall::DecoyCount(range.clone()));
        let count = self
            .decoy_counts
            .pop_front()
            .expect("fixed decoy-count tape must not be exhausted");
        assert!(range.contains(&count));
        count
    }

    fn decoy_salt(&mut self) -> String {
        self.calls.push(RandomCall::DecoySalt);
        self.decoy_salts
            .pop_front()
            .expect("fixed decoy-salt tape must not be exhausted")
    }
}

#[test]
#[cfg(feature = "mock_salts")]
fn all_levels_locks_disclosure_order_digest_assembly_and_signed_payload_bytes() {
    let mut issuer = new_issuer();
    let serialized = issuer
        .issue_sd_jwt(
            nested_claims(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("issuance must succeed");

    let (name_encoded, name_digest) = expected_disclosure(r#"["test-salt-0000", "name", "Alice"]"#);
    let (city_encoded, city_digest) =
        expected_disclosure(r#"["test-salt-0001", "city", "Denver"]"#);
    let (address_encoded, address_digest) = expected_disclosure(&format!(
        r#"["test-salt-0002", "address", {{"_sd": ["{city_digest}"]}}]"#
    ));
    let (role_encoded, role_digest) = expected_disclosure(r#"["test-salt-0003", "admin"]"#);
    let (roles_encoded, roles_digest) = expected_disclosure(&format!(
        r#"["test-salt-0004", "roles", [{{"...": "{role_digest}"}}]]"#
    ));

    let expected_encoded = vec![
        name_encoded,
        city_encoded,
        address_encoded,
        role_encoded,
        roles_encoded,
    ];
    let expected_digests = vec![
        name_digest.clone(),
        city_digest,
        address_digest.clone(),
        role_digest,
        roles_digest.clone(),
    ];
    assert_eq!(
        issuer
            .all_disclosures
            .iter()
            .map(|disclosure| disclosure.raw_b64.clone())
            .collect::<Vec<_>>(),
        expected_encoded
    );
    assert_eq!(
        issuer
            .all_disclosures
            .iter()
            .map(|disclosure| disclosure.hash.clone())
            .collect::<Vec<_>>(),
        expected_digests
    );

    let mut root_digests = [name_digest, address_digest, roles_digest];
    root_digests.sort();
    let expected_payload = format!(
        r#"{{"_sd":["{}","{}","{}"],"_sd_alg":"{}","iss":"https://issuer.example","iat":1,"exp":2}}"#,
        root_digests[0], root_digests[1], root_digests[2], DEFAULT_DIGEST_ALG
    );
    assert_eq!(decoded_jwt_payload(&issuer.signed_sd_jwt), expected_payload);

    let expected_compact = format!("{}~{}~", issuer.signed_sd_jwt, expected_encoded.join("~"));
    assert_eq!(serialized, expected_compact);
}

#[test]
#[cfg(feature = "mock_salts")]
fn fixed_mock_salt_and_holder_key_match_the_golden_compact_credential() {
    let holder_key = || serde_json::from_str::<Jwk>(HOLDER_JWK).expect("holder JWK must be valid");
    let mut first = new_issuer();
    let first = first
        .issue_sd_jwt(
            nested_claims(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(holder_key()),
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("first issuance must succeed");

    let mut second = new_issuer();
    let second = second
        .issue_sd_jwt(
            nested_claims(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(holder_key()),
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("second issuance must succeed");

    assert_eq!(first, GOLDEN_COMPACT_WITH_HOLDER_KEY);
    assert_eq!(second, GOLDEN_COMPACT_WITH_HOLDER_KEY);
}

#[test]
#[cfg(feature = "mock_salts")]
fn serialization_formats_preserve_one_jws_and_one_disclosure_sequence() {
    let issue = |format| {
        let mut issuer = new_issuer();
        issuer
            .issue_sd_jwt(
                nested_claims(),
                ClaimsForSelectiveDisclosureStrategy::TopLevel,
                None,
                false,
                format,
            )
            .expect("issuance must succeed")
    };

    let compact = issue(SDJWTSerializationFormat::Compact);
    let compact_parts = compact.split('~').collect::<Vec<_>>();
    assert_eq!(compact_parts.last(), Some(&""));
    let compact_jws = compact_parts[0].split('.').collect::<Vec<_>>();
    assert_eq!(compact_jws.len(), 3);
    let compact_disclosures = &compact_parts[1..compact_parts.len() - 1];

    let flattened: Value = serde_json::from_str(&issue(SDJWTSerializationFormat::FlattenedJson))
        .expect("flattened serialization must be JSON");
    assert_eq!(flattened["protected"], compact_jws[0]);
    assert_eq!(flattened["payload"], compact_jws[1]);
    assert_eq!(flattened["signature"], compact_jws[2]);
    assert_eq!(
        flattened["header"]["disclosures"],
        json!(compact_disclosures)
    );

    let general: Value = serde_json::from_str(&issue(SDJWTSerializationFormat::GeneralJson))
        .expect("general serialization must be JSON");
    assert_eq!(general["payload"], compact_jws[1]);
    assert_eq!(general["signatures"].as_array().map(Vec::len), Some(1));
    assert_eq!(general["signatures"][0]["protected"], compact_jws[0]);
    assert_eq!(general["signatures"][0]["signature"], compact_jws[2]);
    assert_eq!(
        general["signatures"][0]["header"]["disclosures"],
        json!(compact_disclosures)
    );
}

#[test]
#[cfg(feature = "mock_salts")]
fn custom_paths_restore_nested_object_and_array_results_in_place() {
    let mut issuer = new_issuer();
    issuer
        .issue_sd_jwt(
            json!({
                "name": "visible",
                "address": { "city": "Denver", "zip": 80202 },
                "roles": ["reader", "admin"]
            }),
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.address.city", "$.roles[1]"]),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("custom-path issuance must succeed");

    let (city_encoded, city_digest) =
        expected_disclosure(r#"["test-salt-0000", "city", "Denver"]"#);
    let (role_encoded, role_digest) = expected_disclosure(r#"["test-salt-0001", "admin"]"#);
    assert_eq!(
        issuer
            .all_disclosures
            .iter()
            .map(|disclosure| disclosure.raw_b64.clone())
            .collect::<Vec<_>>(),
        vec![city_encoded, role_encoded]
    );
    assert_eq!(
        issuer.sd_jwt_payload,
        json!({
            "name": "visible",
            "address": { "_sd": [city_digest], "zip": 80202 },
            "roles": ["reader", { SD_LIST_PREFIX: role_digest }],
            "_sd_alg": DEFAULT_DIGEST_ALG
        })
        .as_object()
        .expect("expected payload must be an object")
        .clone()
    );
}

#[test]
#[cfg(not(feature = "mock_salts"))]
fn production_salts_preserve_compact_json_and_bmp_disclosure_bytes() {
    let mut issuer = new_issuer();
    issuer
        .issue_sd_jwt(
            json!({
                "iss": "https://issuer.example",
                "iat": 1,
                "exp": 2,
                "name": "München",
                "profile": { "city": "Denver", "active": true },
                "roles": ["admin", 7]
            }),
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("production-path issuance must succeed");

    let decoded = issuer
        .all_disclosures
        .iter()
        .map(|disclosure| {
            String::from_utf8(
                base64url_decode(&disclosure.raw_b64).expect("disclosure must be valid Base64url"),
            )
            .expect("disclosure must be UTF-8 JSON")
        })
        .collect::<Vec<_>>();
    let salts = decoded
        .iter()
        .map(|disclosure| {
            let parsed: Value =
                serde_json::from_str(disclosure).expect("disclosure must be valid JSON");
            let salt = parsed[0]
                .as_str()
                .expect("disclosure salt must be a string")
                .to_owned();
            assert_eq!(salt.len(), 22);
            assert_eq!(
                base64url_decode(&salt)
                    .expect("salt must be valid Base64url")
                    .len(),
                16
            );
            salt
        })
        .collect::<Vec<_>>();

    assert_eq!(
        decoded[0],
        format!(r#"["{}", "name", "M\u00fcnchen"]"#, salts[0])
    );
    assert_eq!(
        decoded[1],
        format!(
            r#"["{}", "profile", {{"city":"Denver","active":true}}]"#,
            salts[1]
        )
    );
    assert_eq!(
        decoded[2],
        format!(r#"["{}", "roles", ["admin",7]]"#, salts[2])
    );
    for (disclosure, decoded) in issuer.all_disclosures.iter().zip(&decoded) {
        assert_eq!(disclosure.raw_b64, base64url_encode(decoded.as_bytes()));
        assert_eq!(disclosure.hash, base64_hash(disclosure.raw_b64.as_bytes()));
    }

    let mut root_digests = issuer
        .all_disclosures
        .iter()
        .map(|disclosure| disclosure.hash.clone())
        .collect::<Vec<_>>();
    root_digests.sort();
    let expected_payload = format!(
        r#"{{"_sd":["{}","{}","{}"],"_sd_alg":"{}","iss":"https://issuer.example","iat":1,"exp":2}}"#,
        root_digests[0], root_digests[1], root_digests[2], DEFAULT_DIGEST_ALG
    );
    assert_eq!(decoded_jwt_payload(&issuer.signed_sd_jwt), expected_payload);
}

#[test]
#[cfg(not(feature = "mock_salts"))]
fn fixed_random_tape_replays_decoys_and_their_allocation_order() {
    let mut random_source = FixedIssuanceRandomSource::decoy_fixture();
    let mut issuer = new_issuer();
    let serialized = issuer
        .issue_sd_jwt_with_random_source(
            json!({ "name": "Alice" }),
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            None,
            true,
            SDJWTSerializationFormat::Compact,
            &mut random_source,
        )
        .expect("fixed-tape issuance with decoys must succeed");

    random_source.assert_exhausted();
    assert_eq!(
        random_source.calls,
        vec![
            RandomCall::DisclosureSalt,
            RandomCall::DecoyCount(2..5),
            RandomCall::DecoySalt,
            RandomCall::DecoySalt,
            RandomCall::DecoySalt,
        ]
    );
    assert_eq!(issuer.all_disclosures.len(), 1);
    let digests = issuer.sd_jwt_payload[SD_DIGESTS_KEY]
        .as_array()
        .expect("root _sd must be an array");
    assert_eq!(digests.len(), 4);
    let digest_strings = digests
        .iter()
        .map(|digest| digest.as_str().expect("every _sd entry must be a string"))
        .collect::<Vec<_>>();
    assert!(digest_strings.windows(2).all(|pair| pair[0] <= pair[1]));
    for digest in digest_strings {
        assert_eq!(digest.len(), 43);
        assert_eq!(
            base64url_decode(digest)
                .expect("every _sd entry must be valid Base64url")
                .len(),
            32
        );
    }
    assert_eq!(serialized, GOLDEN_COMPACT_WITH_DECOYS);
}

#[test]
#[cfg(not(feature = "mock_salts"))]
fn production_source_acquires_one_rng_and_preserves_scalar_draw_order() {
    let mut random_source = counted_random_source();
    let mut issuer = new_issuer();
    issuer
        .issue_sd_jwt_with_random_source(
            json!({ "name": "Alice" }),
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            None,
            true,
            SDJWTSerializationFormat::Compact,
            &mut random_source,
        )
        .expect("instrumented scalar issuance must succeed");

    assert_eq!(rng_initialization_count(), 1);
    let instrumented_rng = random_source
        .rng
        .as_ref()
        .expect("issuance must retain its initialized RNG");
    assert_eq!(
        instrumented_rng.calls,
        [
            RawRandomCall::FillBytes(16),
            RawRandomCall::NextU32,
            RawRandomCall::FillBytes(16),
            RawRandomCall::FillBytes(16),
            RawRandomCall::FillBytes(16),
        ]
    );
    assert_eq!(instrumented_rng.salt_ordinal, 4);

    let disclosure = String::from_utf8(
        base64url_decode(&issuer.all_disclosures[0].raw_b64)
            .expect("disclosure must be valid Base64url"),
    )
    .expect("disclosure must be UTF-8 JSON");
    let disclosure: Value =
        serde_json::from_str(&disclosure).expect("disclosure must be valid JSON");
    let disclosure_salt = disclosure[0]
        .as_str()
        .expect("disclosure salt must be a string");
    assert_eq!(
        base64url_decode(disclosure_salt).expect("disclosure salt must be Base64url"),
        [0; 16]
    );

    let digests = issuer.sd_jwt_payload[SD_DIGESTS_KEY]
        .as_array()
        .expect("root _sd must be an array");
    assert_eq!(digests.len(), 4);
    for salt_ordinal in 1..=3 {
        let salt = base64url_encode(&[salt_ordinal; 16]);
        let digest = base64_hash(salt.as_bytes());
        assert!(digests.iter().any(|candidate| candidate == &digest));
    }
}

#[test]
#[cfg(not(feature = "mock_salts"))]
fn randomness_free_issuance_does_not_acquire_production_rng() {
    let mut random_source = counted_random_source();
    new_issuer()
        .issue_sd_jwt_with_random_source(
            json!({ "iss": "https://issuer.example", "visible": true }),
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            None,
            false,
            SDJWTSerializationFormat::Compact,
            &mut random_source,
        )
        .expect("randomness-free issuance must succeed");

    assert_eq!(rng_initialization_count(), 0);
    assert!(random_source.rng.is_none());
}

#[test]
#[cfg(not(feature = "mock_salts"))]
fn invalid_issuance_does_not_acquire_production_rng() {
    let mut random_source = counted_random_source();
    let result = new_issuer().issue_sd_jwt_with_random_source(
        json!({ "_sd": [] }),
        ClaimsForSelectiveDisclosureStrategy::TopLevel,
        None,
        true,
        SDJWTSerializationFormat::Compact,
        &mut random_source,
    );

    assert!(result.is_err());
    assert_eq!(rng_initialization_count(), 0);
    assert!(random_source.rng.is_none());
}

#[test]
#[cfg(feature = "mock_salts")]
fn mock_salts_without_decoys_does_not_acquire_production_rng() {
    let _mock_salt_guard = crate::utils::seed_mock_salts_for_test();
    let mut random_source = counted_random_source();
    let mut issuer = new_issuer();
    issuer
        .issue_sd_jwt_with_random_source(
            json!({ "name": "Alice" }),
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            None,
            false,
            SDJWTSerializationFormat::Compact,
            &mut random_source,
        )
        .expect("mock-salt issuance without decoys must succeed");

    assert_eq!(issuer.all_disclosures.len(), 1);
    assert_eq!(rng_initialization_count(), 0);
    assert!(random_source.rng.is_none());
}

#[test]
#[cfg(not(feature = "mock_salts"))]
fn nested_random_tape_locks_child_decoys_before_parent_disclosures() {
    let mut random_source = FixedIssuanceRandomSource::nested_decoy_fixture();
    let mut issuer = new_issuer();
    let serialized = issuer
        .issue_sd_jwt_with_random_source(
            json!({
                "profile": { "city": "Denver" },
                "roles": ["admin"]
            }),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            true,
            SDJWTSerializationFormat::Compact,
            &mut random_source,
        )
        .expect("nested fixed-tape issuance with decoys must succeed");

    random_source.assert_exhausted();
    assert_eq!(
        random_source.calls,
        vec![
            RandomCall::DisclosureSalt,
            RandomCall::DecoyCount(2..5),
            RandomCall::DecoySalt,
            RandomCall::DecoySalt,
            RandomCall::DisclosureSalt,
            RandomCall::DisclosureSalt,
            RandomCall::DisclosureSalt,
            RandomCall::DecoyCount(2..5),
            RandomCall::DecoySalt,
            RandomCall::DecoySalt,
            RandomCall::DecoySalt,
            RandomCall::DecoySalt,
        ]
    );
    assert_eq!(issuer.all_disclosures.len(), 4);
    assert_eq!(
        issuer.sd_jwt_payload[SD_DIGESTS_KEY]
            .as_array()
            .map(Vec::len),
        Some(6)
    );

    let profile_disclosure = String::from_utf8(
        base64url_decode(&issuer.all_disclosures[1].raw_b64)
            .expect("profile disclosure must be valid Base64url"),
    )
    .expect("profile disclosure must be UTF-8 JSON");
    let profile_disclosure: Value =
        serde_json::from_str(&profile_disclosure).expect("profile disclosure must be valid JSON");
    assert_eq!(
        profile_disclosure[2][SD_DIGESTS_KEY]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(serialized, GOLDEN_NESTED_COMPACT_WITH_DECOYS);
}

#[test]
#[cfg(not(feature = "mock_salts"))]
fn public_legacy_random_source_preserves_decoy_shape() {
    let mut issuer = new_issuer();
    issuer
        .issue_sd_jwt(
            json!({ "name": "Alice" }),
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            None,
            true,
            SDJWTSerializationFormat::Compact,
        )
        .expect("public issuance with decoys must succeed");

    assert_eq!(issuer.all_disclosures.len(), 1);
    let real_digest = issuer.all_disclosures[0].hash.as_str();
    let digests = issuer.sd_jwt_payload[SD_DIGESTS_KEY]
        .as_array()
        .expect("root _sd must be an array");
    assert!((3..=5).contains(&digests.len()));
    let digest_strings = digests
        .iter()
        .map(|digest| digest.as_str().expect("every _sd entry must be a string"))
        .collect::<Vec<_>>();
    assert_eq!(
        digest_strings
            .iter()
            .filter(|digest| **digest == real_digest)
            .count(),
        1
    );
    assert!(digest_strings.windows(2).all(|pair| pair[0] <= pair[1]));
    for digest in digest_strings {
        assert_eq!(digest.len(), 43);
        assert_eq!(
            base64url_decode(digest)
                .expect("every _sd entry must be valid Base64url")
                .len(),
            32
        );
    }
}

#[test]
fn reusing_an_issuer_does_not_retain_prior_disclosures() {
    let mut issuer = new_issuer();
    issuer
        .issue_sd_jwt(
            nested_claims(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("first issuance must succeed");
    assert!(!issuer.all_disclosures.is_empty());

    let second = issuer
        .issue_sd_jwt(
            json!({ "iss": "https://issuer.example", "public": "value" }),
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("second issuance must succeed");

    assert!(issuer.all_disclosures.is_empty());
    assert!(issuer.sd_jwt_payload.get(SD_DIGESTS_KEY).is_none());
    assert_eq!(second.split('~').count(), 2);
}
