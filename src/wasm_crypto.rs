//! Pure-Rust verification provider for browser WebAssembly.
//!
//! AWS-LC is the production native backend, but does not support
//! `wasm32-unknown-unknown`. Browser builds therefore retain only the
//! asymmetric algorithms implemented by the fork's existing pure-Rust curve
//! dependencies. RSA is deliberately unavailable on this target instead of
//! reintroducing the vulnerable RustCrypto `rsa` crate.

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use jsonwebtoken::crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier};
use jsonwebtoken::errors::{new_error, ErrorKind, Result};
use jsonwebtoken::jwk::ThumbprintHash;
use jsonwebtoken::signature::{Error as SignatureError, Verifier};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, EncodingKey};
type P256Signature = ecdsa::Signature<p256::NistP256>;
type P256VerifyingKey = p256::PublicKey;
type P384Signature = ecdsa::Signature<p384::NistP384>;
type P384VerifyingKey = p384::PublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};

struct P256Verifier(P256VerifyingKey);
struct P384Verifier(P384VerifyingKey);
struct Ed25519Verifier(Ed25519VerifyingKey);

impl Verifier<Vec<u8>> for P256Verifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &Vec<u8>,
    ) -> std::result::Result<(), SignatureError> {
        let signature =
            P256Signature::from_slice(signature).map_err(SignatureError::from_source)?;
        let digest = Sha256::digest(message);
        let prehash = ecdsa::hazmat::bits2field::<p256::NistP256>(&digest)
            .map_err(SignatureError::from_source)?;
        let public_point = p256::ProjectivePoint::from(*self.0.as_affine());
        ecdsa::hazmat::verify_prehashed::<p256::NistP256>(&public_point, &prehash, &signature)
            .map_err(SignatureError::from_source)
    }
}

impl JwtVerifier for P256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}

impl Verifier<Vec<u8>> for P384Verifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &Vec<u8>,
    ) -> std::result::Result<(), SignatureError> {
        let signature =
            P384Signature::from_slice(signature).map_err(SignatureError::from_source)?;
        let digest = Sha384::digest(message);
        let prehash = ecdsa::hazmat::bits2field::<p384::NistP384>(&digest)
            .map_err(SignatureError::from_source)?;
        let public_point = p384::ProjectivePoint::from(*self.0.as_affine());
        ecdsa::hazmat::verify_prehashed::<p384::NistP384>(&public_point, &prehash, &signature)
            .map_err(SignatureError::from_source)
    }
}

impl JwtVerifier for P384Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES384
    }
}

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

fn verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    match algorithm {
        Algorithm::ES256 if key.family() == AlgorithmFamily::Ec => Ok(Box::new(P256Verifier(
            P256VerifyingKey::from_sec1_bytes(key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ))),
        Algorithm::ES384 if key.family() == AlgorithmFamily::Ec => Ok(Box::new(P384Verifier(
            P384VerifyingKey::from_sec1_bytes(key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ))),
        Algorithm::EdDSA if key.family() == AlgorithmFamily::Ed => {
            let bytes =
                <&[u8; 32]>::try_from(key.as_bytes()).map_err(|_| ErrorKind::InvalidEddsaKey)?;
            Ok(Box::new(Ed25519Verifier(
                Ed25519VerifyingKey::from_bytes(bytes).map_err(|_| ErrorKind::InvalidEddsaKey)?,
            )))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => Err(new_error(ErrorKind::Provider(
            "RSA verification is unavailable in browser WebAssembly builds".to_owned(),
        ))),
        _ => Err(new_error(ErrorKind::InvalidAlgorithm)),
    }
}

fn signer(_algorithm: &Algorithm, _key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    Err(new_error(ErrorKind::Provider(
        "local JWT signing is not supported".to_owned(),
    )))
}

fn digest(data: &[u8], algorithm: ThumbprintHash) -> Vec<u8> {
    match algorithm {
        ThumbprintHash::SHA256 => Sha256::digest(data).to_vec(),
        ThumbprintHash::SHA384 => Sha384::digest(data).to_vec(),
        ThumbprintHash::SHA512 => Sha512::digest(data).to_vec(),
    }
}

static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: signer,
    verifier_factory: verifier,
    jwk_utils: JwkUtils {
        extract_rsa_public_key_components: |_| {
            Err(new_error(ErrorKind::Provider(
                "local RSA key handling is not supported".to_owned(),
            )))
        },
        extract_ec_public_key_coordinates: |_, _| {
            Err(new_error(ErrorKind::Provider(
                "local private-key handling is not supported".to_owned(),
            )))
        },
        compute_digest: digest,
    },
};

pub(crate) fn ensure_installed() -> crate::error::Result<()> {
    validate_install_result(PROVIDER.install_default())
}

fn validate_install_result(
    result: std::result::Result<(), &'static CryptoProvider>,
) -> crate::error::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(installed) if std::ptr::eq(installed, &PROVIDER) => Ok(()),
        Err(_) => Err(crate::error::Error::InvalidState(
            "the required browser cryptography provider is not active".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    static FOREIGN_PROVIDER: CryptoProvider = CryptoProvider {
        signer_factory: signer,
        verifier_factory: verifier,
        jwk_utils: JwkUtils {
            extract_rsa_public_key_components: |_| unreachable!(),
            extract_ec_public_key_coordinates: |_, _| unreachable!(),
            compute_digest: digest,
        },
    };

    #[wasm_bindgen_test]
    fn installs_idempotently_and_rejects_rsa() {
        ensure_installed().unwrap();
        ensure_installed().unwrap();

        let key = DecodingKey::from_rsa_components("AQ", "AQAB").unwrap();
        for algorithm in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ] {
            let error = match verifier(&algorithm, &key) {
                Err(error) => error,
                Ok(_) => panic!("browser provider unexpectedly constructed an RSA verifier"),
            };
            assert!(error
                .to_string()
                .contains("RSA verification is unavailable"));
        }
    }

    #[wasm_bindgen_test]
    fn p256_verifier_accepts_valid_and_rejects_changed_messages() {
        use p256::ecdsa::signature::Signer as _;

        let signing_key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let encoded = signing_key.verifying_key().to_encoded_point(false);
        let key = DecodingKey::from_ec_der(encoded.as_bytes());
        let verifier = verifier(&Algorithm::ES256, &key).unwrap();
        let signature: P256Signature = signing_key.sign(b"message");
        let signature = signature.to_bytes().to_vec();

        assert!(verifier.verify(b"message", &signature).is_ok());
        assert!(verifier.verify(b"changed", &signature).is_err());
    }

    #[wasm_bindgen_test]
    fn p384_verifier_accepts_valid_and_rejects_changed_messages() {
        use p384::ecdsa::signature::Signer as _;

        let signing_key = p384::ecdsa::SigningKey::from_slice(&[8u8; 48]).unwrap();
        let encoded = signing_key.verifying_key().to_encoded_point(false);
        let key = DecodingKey::from_ec_der(encoded.as_bytes());
        let verifier = verifier(&Algorithm::ES384, &key).unwrap();
        let signature: P384Signature = signing_key.sign(b"message");
        let signature = signature.to_bytes().to_vec();

        assert!(verifier.verify(b"message", &signature).is_ok());
        assert!(verifier.verify(b"changed", &signature).is_err());
    }

    #[wasm_bindgen_test]
    fn ed25519_verifier_accepts_valid_and_rejects_changed_messages() {
        use ed25519_dalek::Signer as _;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let key = DecodingKey::from_ed_der(signing_key.verifying_key().as_bytes());
        let verifier = verifier(&Algorithm::EdDSA, &key).unwrap();
        let signature = signing_key.sign(b"message").to_bytes().to_vec();

        assert!(verifier.verify(b"message", &signature).is_ok());
        assert!(verifier.verify(b"changed", &signature).is_err());
    }

    #[wasm_bindgen_test]
    fn ed25519_verifier_rejects_identity_key_forgery() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let key = DecodingKey::from_ed_der(&identity);
        let verifier = verifier(&Algorithm::EdDSA, &key).unwrap();

        let mut forged_signature = vec![0x66; 64];
        forged_signature[0] = 0x58;
        forged_signature[32..].fill(0);
        forged_signature[32] = 1;

        assert!(verifier.verify(b"any message", &forged_signature).is_err());
        assert!(verifier
            .verify(b"a different message", &forged_signature)
            .is_err());
    }

    #[wasm_bindgen_test]
    fn foreign_process_provider_is_rejected() {
        let error = validate_install_result(Err(&FOREIGN_PROVIDER)).unwrap_err();
        assert!(error
            .to_string()
            .contains("required browser cryptography provider is not active"));
    }
}
