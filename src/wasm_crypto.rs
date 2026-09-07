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
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
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
        self.0
            .verify(message, &signature)
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
        self.0
            .verify(message, &signature)
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
            .verify(message, &signature)
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

pub(crate) fn ensure_installed() {
    // A host application may deliberately install its own provider first. In
    // that case jsonwebtoken returns the installed provider and we leave the
    // process-wide choice intact.
    let _ = PROVIDER.install_default();
}
