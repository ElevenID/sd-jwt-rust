//! Verification-only cryptography provider for native targets.
//!
//! Curve verification uses the same maintained libraries as the browser
//! provider. RSA verification is delegated to AWS-LC without enabling either
//! of jsonwebtoken's process-global backend features.

use aws_lc_rs::signature as aws_signature;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use jsonwebtoken::crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier};
use jsonwebtoken::errors::{new_error, ErrorKind, Result};
use jsonwebtoken::jwk::ThumbprintHash;
use jsonwebtoken::signature::{Error as SignatureError, Verifier};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, EncodingKey};
type P256Signature = ecdsa::Signature<p256::NistP256>;
type P256VerifyingKey = p256::PublicKey;
type P384Signature = ecdsa::Signature<p384::NistP384>;
type P384VerifyingKey = p384::PublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};

struct P256Verifier(P256VerifyingKey);
struct P384Verifier(P384VerifyingKey);
struct Ed25519Verifier(Ed25519VerifyingKey);
struct RsaVerifier {
    algorithm: Algorithm,
    key: DecodingKey,
}

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
                let prehash = ecdsa::hazmat::bits2field::<$curve>(&digest)
                    .map_err(SignatureError::from_source)?;
                let public_point = <$projective>::from(*self.0.as_affine());
                ecdsa::hazmat::verify_prehashed::<$curve>(&public_point, &prehash, &signature)
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

fn rsa_parameters(algorithm: Algorithm) -> &'static aws_signature::RsaParameters {
    match algorithm {
        Algorithm::RS256 => &aws_signature::RSA_PKCS1_2048_8192_SHA256,
        Algorithm::RS384 => &aws_signature::RSA_PKCS1_2048_8192_SHA384,
        Algorithm::RS512 => &aws_signature::RSA_PKCS1_2048_8192_SHA512,
        Algorithm::PS256 => &aws_signature::RSA_PSS_2048_8192_SHA256,
        Algorithm::PS384 => &aws_signature::RSA_PSS_2048_8192_SHA384,
        Algorithm::PS512 => &aws_signature::RSA_PSS_2048_8192_SHA512,
        _ => unreachable!("RsaVerifier is constructed only for RSA algorithms"),
    }
}

impl Verifier<Vec<u8>> for RsaVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &Vec<u8>,
    ) -> std::result::Result<(), SignatureError> {
        let parameters = rsa_parameters(self.algorithm);
        match self.key.kind() {
            DecodingKeyKind::SecretOrDer(bytes) => {
                aws_signature::UnparsedPublicKey::new(parameters, bytes)
                    .verify(message, signature)
                    .map_err(SignatureError::from_source)
            }
            DecodingKeyKind::RsaModulusExponent { n, e } => {
                aws_signature::RsaPublicKeyComponents { n, e }
                    .verify(parameters, message, signature)
                    .map_err(SignatureError::from_source)
            }
        }
    }
}

impl JwtVerifier for RsaVerifier {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
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
        | Algorithm::PS512
            if key.family() == AlgorithmFamily::Rsa =>
        {
            Ok(Box::new(RsaVerifier {
                algorithm: *algorithm,
                key: key.clone(),
            }))
        }
        _ => Err(new_error(ErrorKind::InvalidAlgorithm)),
    }
}

// Library unit tests construct signed public fixtures. Production builds
// deliberately compile no local-signing route through this provider.
#[cfg(test)]
fn signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    (jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.signer_factory)(algorithm, key)
}

#[cfg(not(test))]
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
                "local RSA private-key handling is not supported".to_owned(),
            )))
        },
        extract_ec_public_key_coordinates: |_, _| {
            Err(new_error(ErrorKind::Provider(
                "local EC private-key handling is not supported".to_owned(),
            )))
        },
        compute_digest: digest,
    },
};

pub(crate) fn ensure_installed() -> crate::error::Result<()> {
    match PROVIDER.install_default() {
        Ok(()) => Ok(()),
        Err(installed) if std::ptr::eq(installed, &PROVIDER) => Ok(()),
        Err(_) => Err(crate::error::Error::InvalidState(
            "the required native cryptography provider is not active".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair as _;

    const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC8rUj8OT3yKej3\nmQFlOO8ZYGNBcWUzdpPotih5ogCMnUA+kekZ9wbvw8m4YTpwlD/S3g/hdbUBHRDx\nxIHG0xmmTM+vfQVb2xgXZCgriXmX/eBhWIGpv/r7R7YWDhhVCmc55KcJivSbh3E7\nzehccigOIWTJ9AVoaFRGYxp8hN4saMv9hNVojxVgizFKg+yFFvVLOjO78WX0i3RJ\nRXJf7g5UeP/Bs0TAMbkVO/fBpUjOJKcT59jdl1/7u0WCTMTfpyt3eLXTtivhh6QE\n6zNWZ3TaB1FFP4SQ8+B8UpoVub4SoUsUpt1kytM5lI1+8BBuwO1izF+awnMts9sg\n5SzvjE63AgMBAAECggEAOhUiRbsdbcInHKm2e0G2oVpB0/Cjld8oE1iYRzFu99qk\n314tozefpAnivGb6BZQtva1suBxzNz+KatLynJF58O7udHiJQMjGttS3ZQeyLe8S\ntwT3DZmzGs3tqQZ3yR4lvvW70j07pfFhE2cE5Aikeg0fqOf9DjIn129ExRZmCsdD\nR7NnblNhDdqmkFiPgbhBqxxDOFPiQyFH2PvR1Pj8b7p6nlCZSrmqesHmTYjFOAEv\nNNz48OuRVV1pGxaEwyT5PaOkW0OKZvlibyaeuFr8jbdtSA4Vh+yePmfExsol0L1I\nvoPYTRjVCxkAGRq0KgkeRwysMk2tQbIvf8vjWQumwQKBgQD/Q4a8Gl3VliK2F9yL\nTwlC6XjAcBLrXc4cL4lttvgB7YyoQB8UvHAySbJoDgBPaPaqbofws6YieMsd1oeY\nVMSzTeXJkMQC3VkKYUaO5IlMFT5PD2F967fJZV/q2V+BL6s6Vsl1PqnHyP1w54qk\n4s02qoJBU+FuFCeUGZyXnar5lwKBgQC9OJgt6m8g49pvguj1TPKJmEfzBBySOmuj\n4C52XlbvrYaVpYyhQnckJUgZIWcx2fA9W/D4PfwFzsiItbxep9GgULIMix9C1PTV\ns7go3gHHQfmOgZpmJH2Tand1qKdhDTOWjKZJzDNdo81rAgYsW+Hx+anquM1bi4cC\nUWHYXoS34QKBgHmMxxC1IW9+QWMiM6OmbAuPry87btbi4S1suW0kDi6k1jCb7/Do\n1igsDacc26r0mViIr3S/puGNUXMQ35p66vtSoZP8ukl+61JVBcsvKe2vw+7TrSHP\n58Ef46+p+J9Eeq2Z++43e5MlswFbUBq54Owh/0pqTdMkB8Cu/XD45BxbAoGBAId0\ncyQzdZgi5KT9Hs0zZ1Bujdr+r4FShunKOxiLUkrDetu3piNulCFw+tramagLLrqO\nDcN3g+mYbN/I0W8lTaApBDyMfzV1g0tUG1pOCxHcPczxJFlIeAjGp3u33xJPxAVa\n7FNZ9c9rykp3KXop0GZLZoLcBk4pZN2Y6qVcjD+hAoGBANXlp2ZCuCYws17lCT+I\nxHlUJDu9t6o6rJGYezXFyrzrZDDS6CrrqARXqOFSKpfZN1f8dHsdaLafqBb9iADe\noqLZ4c0NyDjyxLBhiht/NDrMcfxf5FLrwmdO/iV6Hn6GWVvS8s3x4mYKuns5sJ6b\nYTa2y89NkNgCn0f1CWNdFbJk\n-----END PRIVATE KEY-----\n";

    #[test]
    fn installs_idempotently() {
        ensure_installed().unwrap();
        ensure_installed().unwrap();
    }

    #[test]
    fn native_curve_verifiers_accept_valid_and_reject_changed_messages() {
        use p256::ecdsa::signature::Signer as _;

        let p256_signing_key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let p256_encoded = p256_signing_key.verifying_key().to_encoded_point(false);
        let p256_key = DecodingKey::from_ec_der(p256_encoded.as_bytes());
        let p256_verifier = verifier(&Algorithm::ES256, &p256_key).unwrap();
        let p256_signature: p256::ecdsa::Signature = p256_signing_key.sign(b"message");
        let p256_signature = p256_signature.to_bytes().to_vec();
        assert!(p256_verifier.verify(b"message", &p256_signature).is_ok());
        assert!(p256_verifier.verify(b"changed", &p256_signature).is_err());

        let p384_signing_key = p384::ecdsa::SigningKey::from_slice(&[8u8; 48]).unwrap();
        let p384_encoded = p384_signing_key.verifying_key().to_encoded_point(false);
        let p384_key = DecodingKey::from_ec_der(p384_encoded.as_bytes());
        let p384_verifier = verifier(&Algorithm::ES384, &p384_key).unwrap();
        let p384_signature: p384::ecdsa::Signature = p384_signing_key.sign(b"message");
        let p384_signature = p384_signature.to_bytes().to_vec();
        assert!(p384_verifier.verify(b"message", &p384_signature).is_ok());
        assert!(p384_verifier.verify(b"changed", &p384_signature).is_err());
    }

    #[test]
    fn native_ed25519_verifier_rejects_identity_key_forgery() {
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

    #[test]
    fn every_native_rsa_algorithm_accepts_valid_and_rejects_changed_messages() {
        let encoding_key = EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY.as_bytes()).unwrap();
        let key_pair = aws_signature::RsaKeyPair::from_der(encoding_key.inner()).unwrap();
        let public = aws_signature::RsaPublicKeyComponents::<Vec<u8>>::from(key_pair.public_key());
        let decoding_key = DecodingKey::from_rsa_raw_components(&public.n, &public.e);

        for algorithm in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ] {
            let signer = (jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.signer_factory)(
                &algorithm,
                &encoding_key,
            )
            .unwrap();
            let signature = signer.try_sign(b"message").unwrap();
            let verifier = verifier(&algorithm, &decoding_key).unwrap();

            assert!(
                verifier.verify(b"message", &signature).is_ok(),
                "{algorithm:?}"
            );
            assert!(
                verifier.verify(b"changed", &signature).is_err(),
                "{algorithm:?}"
            );
        }
    }
}
