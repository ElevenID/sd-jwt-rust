// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(test, not(feature = "mock_salts")))]
use crate::utils::generate_salt;
#[cfg(all(test, feature = "mock_salts"))]
use crate::utils::generate_salt_mock;
use crate::utils::{base64_hash, base64url_encode};
use serde_json::Value;

#[derive(Debug)]
pub(crate) struct SDJWTDisclosure {
    pub raw_b64: String,
    pub hash: String,
}

impl SDJWTDisclosure {
    #[cfg(test)]
    pub(crate) fn new<V>(key: Option<String>, value: V) -> Self
    where
        V: ToString,
    {
        #[cfg(not(feature = "mock_salts"))]
        let salt = generate_salt();

        #[cfg(feature = "mock_salts")]
        let salt = generate_salt_mock();

        Self::new_with_salt(key, value, salt)
    }

    pub(crate) fn new_with_salt<V>(key: Option<String>, value: V, salt: String) -> Self
    where
        V: ToString,
    {
        let mut value_str = value.to_string();

        #[cfg(feature = "mock_salts")]
        {
            value_str = value_str
                .replace(":[", ": [")
                .replace(',', ", ")
                .replace("\":", "\": ")
                .replace("\":  ", "\": ");
        }

        if !value_str.is_ascii() {
            value_str = escape_unicode_chars(&value_str);
        }

        let data = if let Some(key) = &key {
            format!(r#"["{}", {}, {}]"#, salt, escape_json(key), value_str)
        } else {
            format!(r#"["{salt}", {value_str}]"#)
        };

        let raw_b64 = base64url_encode(data.as_bytes());
        let hash = base64_hash(raw_b64.as_bytes());

        Self { raw_b64, hash }
    }
}

fn escape_unicode_chars(s: &str) -> String {
    let mut result = String::new();

    for c in s.chars() {
        if c.is_ascii() {
            result.push(c);
        } else {
            let mut utf16 = [0; 2];
            for code_unit in c.encode_utf16(&mut utf16) {
                result.push_str(&format!("\\u{code_unit:04x}"));
            }
        }
    }

    result
}

fn escape_json(s: &str) -> String {
    Value::String(String::from(s)).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::base64url_decode;
    use regex::Regex;

    #[test]
    fn test_sdjwt_disclosure_when_key_is_none() {
        #[cfg(feature = "mock_salts")]
        let _mock_salt_guard = crate::utils::seed_mock_salts_for_test();
        let sdjwt_disclosure = SDJWTDisclosure::new(None, "test");
        let decoded_disclosure: String =
            String::from_utf8(base64url_decode(&sdjwt_disclosure.raw_b64).unwrap()).unwrap();

        let re = Regex::new(r#"\[".*", test]"#).unwrap();
        assert!(re.is_match(&decoded_disclosure));
    }

    #[test]
    fn test_sdjwt_disclosure_when_key_is_present() {
        #[cfg(feature = "mock_salts")]
        let _mock_salt_guard = crate::utils::seed_mock_salts_for_test();
        let sdjwt_disclosure = SDJWTDisclosure::new(Some("key".to_string()), "test");
        let decoded =
            String::from_utf8(base64url_decode(&sdjwt_disclosure.raw_b64).unwrap()).unwrap();

        let re = Regex::new(r#"\[".*", "key", test]"#).unwrap();
        assert!(re.is_match(&decoded));
    }

    fn legacy_bmp_escape(c: char) -> String {
        let escaped = c.escape_unicode().to_string();
        match escaped.chars().count() {
            6 => escaped.replace("\\u{", "\\u00").replace('}', ""),
            7 => escaped.replace("\\u{", "\\u0").replace('}', ""),
            8 => escaped.replace("\\u{", "\\u").replace('}', ""),
            _ => panic!("test input was not a non-ASCII BMP scalar"),
        }
    }

    #[test]
    fn utf16_escape_preserves_every_existing_bmp_scalar_byte() {
        for code_point in 0x80..=0xffff {
            let Some(c) = char::from_u32(code_point) else {
                continue;
            };
            assert_eq!(escape_unicode_chars(&c.to_string()), legacy_bmp_escape(c));
        }
    }

    #[test]
    fn supplementary_scalars_use_exact_json_surrogate_pairs_and_disclosure_bytes() {
        for (source, escaped) in [
            ("\u{10000}", "\\ud800\\udc00"),
            ("\u{1f600}", "\\ud83d\\ude00"),
            ("\u{10ffff}", "\\udbff\\udfff"),
        ] {
            assert_eq!(escape_unicode_chars(source), escaped);

            let disclosure = SDJWTDisclosure::new_with_salt(
                Some("claim".to_owned()),
                serde_json::json!(source),
                "salt".to_owned(),
            );
            let expected = format!(r#"["salt", "claim", "{escaped}"]"#);
            let decoded =
                String::from_utf8(base64url_decode(&disclosure.raw_b64).unwrap()).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(disclosure.raw_b64, base64url_encode(expected.as_bytes()));
            assert_eq!(disclosure.hash, base64_hash(disclosure.raw_b64.as_bytes()));

            let parsed: Value = serde_json::from_str(&decoded).unwrap();
            assert_eq!(parsed[2], source);
        }
    }
}
