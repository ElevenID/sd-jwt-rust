use jsonwebtoken::Algorithm;
#[cfg(any(feature = "holder", feature = "issuer-completion"))]
use jsonwebtoken::DecodingKey;

use crate::error::{Error, Result};

/// Smallest supported remote RSA signature (2048-bit modulus).
pub(crate) const MIN_REMOTE_RSA_SIGNATURE_BYTES: usize = 256;
/// Largest supported remote RSA signature (8192-bit modulus).
pub(crate) const MAX_REMOTE_RSA_SIGNATURE_BYTES: usize = 1024;

pub(crate) fn validate_remote_signature(algorithm: Algorithm, signature: &[u8]) -> Result<()> {
    let valid = match algorithm {
        Algorithm::ES256 => ecdsa::Signature::<p256::NistP256>::from_slice(signature).is_ok(),
        Algorithm::ES384 => ecdsa::Signature::<p384::NistP384>::from_slice(signature).is_ok(),
        Algorithm::EdDSA => validate_ed25519_encoding(signature),
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            (MIN_REMOTE_RSA_SIGNATURE_BYTES..=MAX_REMOTE_RSA_SIGNATURE_BYTES)
                .contains(&signature.len())
                && signature.iter().any(|byte| *byte != 0)
        }
        _ => {
            return Err(Error::InvalidInput(format!(
                "unsupported remote signing algorithm: {algorithm:?}"
            )))
        }
    };
    if !valid {
        return Err(Error::InvalidInput(format!(
            "invalid {algorithm:?} remote signature encoding: got {} bytes",
            signature.len()
        )));
    }
    Ok(())
}

#[cfg(any(feature = "holder", feature = "issuer-completion"))]
pub(crate) fn verify_remote_signature(
    algorithm: Algorithm,
    signing_input: &[u8],
    signature: &[u8],
    verification_key: &DecodingKey,
) -> Result<()> {
    validate_remote_signature(algorithm, signature)?;
    crate::install_crypto_provider()?;
    let encoded_signature = crate::utils::base64url_encode(signature);
    match jsonwebtoken::crypto::verify(
        &encoded_signature,
        signing_input,
        verification_key,
        algorithm,
    ) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(Error::InvalidInput(
            "remote signature does not match the prepared signing input and public key".to_owned(),
        )),
    }
}

fn validate_ed25519_encoding(signature: &[u8]) -> bool {
    let Ok(bytes) = <&[u8; 64]>::try_from(signature) else {
        return false;
    };
    let (encoded_r, encoded_s) = bytes.split_at(32);
    let Ok(encoded_r) = <[u8; 32]>::try_from(encoded_r) else {
        return false;
    };
    let Ok(encoded_s) = <[u8; 32]>::try_from(encoded_s) else {
        return false;
    };
    let Some(point) = curve25519_dalek::edwards::CompressedEdwardsY(encoded_r).decompress() else {
        return false;
    };
    point.compress().to_bytes() == encoded_r
        && !point.is_small_order()
        && bool::from(curve25519_dalek::scalar::Scalar::from_canonical_bytes(encoded_s).is_some())
        && signature.iter().any(|byte| *byte != 0)
}
