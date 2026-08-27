// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error;
use crate::error::Error;
use crate::error::Error::DeserializationError;

use base64::engine::general_purpose;
use base64::Engine;
use error::Result;
#[cfg(feature = "mock_salts")]
use lazy_static::lazy_static;
use rand::prelude::ThreadRng;
use rand::RngCore;
use serde_json::Value;
use sha2::Digest;
#[cfg(all(feature = "mock_salts", test))]
use std::sync::MutexGuard;
#[cfg(feature = "mock_salts")]
use std::{collections::VecDeque, sync::Mutex};

#[cfg(feature = "mock_salts")]
lazy_static! {
    pub static ref SALTS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
}

#[cfg(all(feature = "mock_salts", test))]
static MOCK_SALT_TEST_LOCK: Mutex<()> = Mutex::new(());

#[doc(hidden)]
pub fn base64_hash(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

pub(crate) fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[doc(hidden)]
pub fn base64url_decode(b64data: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(b64data)
        .map_err(|e| Error::DeserializationError(e.to_string()))
}

pub(crate) fn generate_salt() -> String {
    let mut buf = [0u8; 16];
    ThreadRng::default().fill_bytes(&mut buf);
    base64url_encode(&buf)
}

#[cfg(feature = "mock_salts")]
pub(crate) fn generate_salt_mock() -> String {
    let salt = SALTS.lock().unwrap().pop_front();
    salt.expect("SALTS is empty")
}

#[cfg(all(feature = "mock_salts", test))]
pub(crate) fn seed_mock_salts_for_test() -> MutexGuard<'static, ()> {
    let guard = MOCK_SALT_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    {
        let mut salts = SALTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        salts.clear();
        salts.extend((0..4096).map(|ordinal| format!("test-salt-{ordinal:04}")));
    }
    guard
}

pub(crate) fn jwt_payload_decode(b64data: &str) -> Result<serde_json::Map<String, Value>> {
    serde_json::from_str(
        &String::from_utf8(
            base64url_decode(b64data).map_err(|e| DeserializationError(e.to_string()))?,
        )
        .map_err(|e| DeserializationError(e.to_string()))?,
    )
    .map_err(|e| DeserializationError(e.to_string()))
}

#[cfg(all(test, feature = "mock_salts"))]
mod tests {
    use super::{generate_salt_mock, seed_mock_salts_for_test, SALTS};

    #[test]
    fn mock_salts_remain_strict_fifo_without_poisoning_the_queue() {
        let _guard = seed_mock_salts_for_test();
        {
            let mut salts = SALTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            salts.clear();
            salts.extend(["first".to_string(), "second".to_string()]);
        }

        assert_eq!(generate_salt_mock(), "first");
        assert_eq!(generate_salt_mock(), "second");
        assert!(std::panic::catch_unwind(generate_salt_mock).is_err());

        SALTS
            .lock()
            .expect("salt exhaustion must not poison the fixture queue")
            .push_back("after-exhaustion".to_string());
        assert_eq!(generate_salt_mock(), "after-exhaustion");
    }
}
