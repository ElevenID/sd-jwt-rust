mod utils;

use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use sd_jwt_rs::batch::{
    preprocess_disclosure_verification_batch,
    preprocess_disclosure_verification_batch_with_executor, CredentialDisclosures,
    DisclosureVerificationBatchPlan, DisclosureVerificationExecutor, DisclosureVerificationJob,
    DisclosureVerificationOutcome,
};
use sd_jwt_rs::error::Result;
use sd_jwt_rs::utils::base64_hash;
use sd_jwt_rs::{SDJWTSerializationFormat, SDJWTVerifier};
use serde_json::{json, Value};
use utils::fixtures::{ISSUER_KEY, ISSUER_PUBLIC_KEY};

const OBJECT_DISCLOSURE: &str = "WyJzYWx0IiwibmFtZSIsIkFsaWNlIl0";
const ARRAY_DISCLOSURE: &str = "WyJhcnJheS1zYWx0Iiw0Ml0";
const INVALID_BASE64_DISCLOSURE: &str = "%";
const INVALID_JSON_DISCLOSURE: &str = "ew";

struct ReverseExecutor;

impl DisclosureVerificationExecutor for ReverseExecutor {
    fn execute<'a>(
        &self,
        jobs: &[DisclosureVerificationJob<'a>],
    ) -> Result<Vec<DisclosureVerificationOutcome<'a>>> {
        Ok(jobs
            .iter()
            .rev()
            .map(DisclosureVerificationJob::process)
            .collect())
    }
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn fixed_presentation() -> (String, Value) {
    let claims = json!({
        "iss": "https://issuer.example",
        "exp": 1883000000,
        "_sd_alg": "sha-256",
        "_sd": [base64_hash(OBJECT_DISCLOSURE.as_bytes())]
    });
    let signed = encode(
        &Header::new(Algorithm::ES256),
        &claims,
        &EncodingKey::from_ec_pem(ISSUER_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    (
        format!("{signed}~{OBJECT_DISCLOSURE}~"),
        json!({
            "iss": "https://issuer.example",
            "exp": 1883000000,
            "name": "Alice"
        }),
    )
}

fn verify(presentation: String) -> Result<Value> {
    SDJWTVerifier::new(
        presentation,
        Box::new(|_, _| DecodingKey::from_ec_pem(ISSUER_PUBLIC_KEY.as_bytes()).unwrap()),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    )
    .map(|verifier| verifier.verified_claims)
}

fn compact_disclosures(presentation: &str) -> Vec<String> {
    presentation
        .split('~')
        .skip(1)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn preprocessing_preserves_disclosure_bytes_alongside_independent_full_verification() {
    let (presentation, claims) = fixed_presentation();
    let disclosures = compact_disclosures(&presentation);
    let single_claims = verify(presentation).unwrap();

    let batch =
        preprocess_disclosure_verification_batch(&[CredentialDisclosures::new(&disclosures)])
            .unwrap();

    assert_eq!(single_claims, claims);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].credential_id().ordinal(), 0);
    assert_eq!(batch[0].ordered_digests().len(), disclosures.len());
    for (digest, encoded) in batch[0].encoded_disclosures() {
        assert_eq!(
            encoded,
            &disclosures[batch[0]
                .ordered_digests()
                .iter()
                .position(|candidate| candidate == digest)
                .unwrap()]
        );
        assert!(batch[0].decoded_disclosures().contains_key(digest));
    }
}

#[test]
fn serial_batch_preserves_single_verifier_error_variant_message() {
    let (presentation, _) = fixed_presentation();
    let mut parts = presentation
        .split('~')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    parts[1] = INVALID_BASE64_DISCLOSURE.to_owned();
    let malformed_presentation = parts.join("~");
    let disclosures = compact_disclosures(&malformed_presentation);

    let single_error = verify(malformed_presentation).unwrap_err();
    let batch_error =
        preprocess_disclosure_verification_batch(&[CredentialDisclosures::new(&disclosures)])
            .unwrap_err();

    assert_eq!(
        std::mem::discriminant(&single_error),
        std::mem::discriminant(&batch_error)
    );
    assert_eq!(single_error.to_string(), batch_error.to_string());
}

#[test]
fn shuffled_outcomes_restore_to_their_credential_and_local_order() {
    let first = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
    let second = owned(&[ARRAY_DISCLOSURE]);
    let results = preprocess_disclosure_verification_batch_with_executor(
        &[
            CredentialDisclosures::new(&first),
            CredentialDisclosures::new(&second),
        ],
        &ReverseExecutor,
    )
    .unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].credential_id().ordinal(), 0);
    assert_eq!(results[1].credential_id().ordinal(), 1);
    assert_eq!(results[0].ordered_digests().len(), 2);
    assert_eq!(results[1].ordered_digests().len(), 1);
    assert_eq!(results[0].encoded_disclosures().len(), 2);
    assert_eq!(results[1].encoded_disclosures().len(), 1);
}

#[test]
fn assembly_rejects_missing_duplicate_and_foreign_identities_without_payloads() {
    let secret = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
    let inputs = [CredentialDisclosures::new(&secret)];
    let plan = DisclosureVerificationBatchPlan::new(&inputs).unwrap();
    let mut complete = plan
        .jobs()
        .iter()
        .map(DisclosureVerificationJob::process)
        .collect::<Vec<_>>();
    let missing = complete.pop().unwrap();
    let missing_error = plan.assemble(complete).unwrap_err();
    assert!(missing_error.to_string().contains("no outcome"));
    assert!(!missing_error.to_string().contains(OBJECT_DISCLOSURE));

    let plan = DisclosureVerificationBatchPlan::new(&inputs).unwrap();
    let mut duplicate = plan
        .jobs()
        .iter()
        .map(DisclosureVerificationJob::process)
        .collect::<Vec<_>>();
    duplicate.pop();
    duplicate.push(plan.jobs()[0].process());
    let duplicate_error = plan.assemble(duplicate).unwrap_err();
    assert!(duplicate_error.to_string().contains("missing or duplicate"));
    assert!(!duplicate_error.to_string().contains(OBJECT_DISCLOSURE));

    let local = DisclosureVerificationBatchPlan::new(&inputs).unwrap();
    let foreign = DisclosureVerificationBatchPlan::new(&inputs).unwrap();
    let foreign_error = local
        .assemble(
            foreign
                .jobs()
                .iter()
                .map(DisclosureVerificationJob::process)
                .collect(),
        )
        .unwrap_err();
    assert!(foreign_error.to_string().contains("foreign plan identity"));
    assert!(!foreign_error.to_string().contains(OBJECT_DISCLOSURE));

    drop(missing);
}

#[test]
fn mixed_errors_use_lowest_credential_then_local_ordinal_and_publish_nothing() {
    let first = owned(&[OBJECT_DISCLOSURE, INVALID_JSON_DISCLOSURE]);
    let second = owned(&[INVALID_BASE64_DISCLOSURE]);
    let error = preprocess_disclosure_verification_batch_with_executor(
        &[
            CredentialDisclosures::new(&first),
            CredentialDisclosures::new(&second),
        ],
        &ReverseExecutor,
    )
    .unwrap_err();

    assert!(error.to_string().contains("Error parsing disclosure ew"));
    assert!(!error.to_string().contains("Error decoding disclosure %"));
}

#[test]
fn empty_single_and_multiple_credential_batches_preserve_caller_order() {
    assert!(preprocess_disclosure_verification_batch(&[])
        .unwrap()
        .is_empty());

    let empty = Vec::new();
    let one = owned(&[OBJECT_DISCLOSURE]);
    let many = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
    let results = preprocess_disclosure_verification_batch(&[
        CredentialDisclosures::new(&empty),
        CredentialDisclosures::new(&one),
        CredentialDisclosures::new(&many),
    ])
    .unwrap();

    assert_eq!(
        results
            .iter()
            .map(|result| result.credential_id().ordinal())
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.ordered_digests().len())
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
}

#[test]
fn repeated_serial_batches_have_identical_public_results_while_plans_remain_isolated() {
    let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
    let inputs = [CredentialDisclosures::new(&disclosures)];

    let first = preprocess_disclosure_verification_batch(&inputs).unwrap();
    let second = preprocess_disclosure_verification_batch(&inputs).unwrap();

    assert_eq!(first, second);
    assert_eq!(first[0].credential_id(), second[0].credential_id());

    let first_plan = DisclosureVerificationBatchPlan::new(&inputs).unwrap();
    let second_plan = DisclosureVerificationBatchPlan::new(&inputs).unwrap();
    assert_eq!(first_plan.jobs()[0].id(), second_plan.jobs()[0].id());
    let error = first_plan
        .assemble(
            second_plan
                .jobs()
                .iter()
                .map(DisclosureVerificationJob::process)
                .collect(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("foreign plan identity"));
}
