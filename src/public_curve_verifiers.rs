//! Public ECDSA and strict Ed25519 verification shared by native and browser providers.

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use jsonwebtoken::crypto::JwtVerifier;
use jsonwebtoken::signature::{Error as SignatureError, Verifier};
use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256, Sha384};

type P256Signature = ecdsa::Signature<p256::NistP256>;
type P384Signature = ecdsa::Signature<p384::NistP384>;

pub(crate) struct P256Verifier(pub(crate) p256::PublicKey);
pub(crate) struct P384Verifier(pub(crate) p384::PublicKey);
pub(crate) struct Ed25519Verifier(pub(crate) Ed25519VerifyingKey);

macro_rules! impl_curve_verifier {
    ($name:ident, $signature:ty, $curve:ty, $projective:ty, $digest:ty, $algorithm:expr) => {
        impl Verifier<Vec<u8>> for $name {
            fn verify(
                &self,
                message: &[u8],
                signature: &Vec<u8>,
            ) -> std::result::Result<(), SignatureError> {
                let signature =
                    <$signature>::from_slice(signature).map_err(SignatureError::from_source)?;
                let digest = <$digest>::digest(message);
                let public_point = <$projective>::from(*self.0.as_affine());
                ecdsa::hazmat::verify_prehashed::<$curve>(&public_point, &digest, &signature)
                    .map_err(SignatureError::from_source)
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $algorithm
            }
        }
    };
}

impl_curve_verifier!(
    P256Verifier,
    P256Signature,
    p256::NistP256,
    p256::ProjectivePoint,
    Sha256,
    Algorithm::ES256
);
impl_curve_verifier!(
    P384Verifier,
    P384Signature,
    p384::NistP384,
    p384::ProjectivePoint,
    Sha384,
    Algorithm::ES384
);

impl Verifier<Vec<u8>> for Ed25519Verifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &Vec<u8>,
    ) -> std::result::Result<(), SignatureError> {
        let signature =
            Ed25519Signature::from_slice(signature).map_err(SignatureError::from_source)?;
        self.0
            .verify_strict(message, &signature)
            .map_err(SignatureError::from_source)
    }
}

impl JwtVerifier for Ed25519Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn shared_adapters_verify_fixed_public_vectors_without_signing_keys() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/public_curve_provider.json"))
                .unwrap();
        for vector in vectors["cases"].as_array().unwrap() {
            let key = hex(vector["public_sec1"].as_str().unwrap());
            let verifier: Box<dyn JwtVerifier> = match vector["algorithm"].as_str().unwrap() {
                "ES256" => Box::new(P256Verifier(
                    p256::PublicKey::from_sec1_bytes(&key).unwrap(),
                )),
                "ES384" => Box::new(P384Verifier(
                    p384::PublicKey::from_sec1_bytes(&key).unwrap(),
                )),
                _ => unreachable!(),
            };
            let signature = hex(vector["signature"].as_str().unwrap());
            assert!(verifier
                .verify(vector["message"].as_str().unwrap().as_bytes(), &signature)
                .is_ok());
            assert!(verifier.verify(b"changed", &signature).is_err());
            assert!(verifier
                .verify(b"changed", &vec![0; signature.len() - 1])
                .is_err());
        }
    }
}
