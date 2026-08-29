// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use super::{ClaimsForSelectiveDisclosureStrategy, SDJWTIssuer};
use crate::utils::{base64_hash, base64url_decode, base64url_encode};
#[cfg(feature = "mock_salts")]
use crate::SD_LIST_PREFIX;
use crate::{SDJWTSerializationFormat, DEFAULT_DIGEST_ALG, SD_DIGESTS_KEY};
#[cfg(feature = "mock_salts")]
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::EncodingKey;
use serde_json::{json, Value};

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
