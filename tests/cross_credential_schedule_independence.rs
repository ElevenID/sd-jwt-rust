use sd_jwt_rs::batch::{
    preprocess_disclosure_verification_batch,
    preprocess_disclosure_verification_batch_with_executor, CredentialDisclosures,
    DisclosureVerificationExecutor, DisclosureVerificationJob, DisclosureVerificationOutcome,
};
use sd_jwt_rs::error::{Error, Result};
use std::cell::Cell;

const OBJECT_DISCLOSURE: &str = "WyJzYWx0IiwibmFtZSIsIkFsaWNlIl0";
const ARRAY_DISCLOSURE: &str = "WyJhcnJheS1zYWx0Iiw0Ml0";
const INVALID_BASE64_DISCLOSURE: &str = "%";
const INVALID_JSON_DISCLOSURE: &str = "ew";
const SEEDED_SCHEDULE: u64 = 0x9e37_79b9_7f4a_7c15;
const GENERIC_EXECUTOR_FAILURE: &str = "Cross-credential disclosure executor failure";

#[derive(Clone, Copy, Debug)]
enum Schedule {
    Serial,
    Reverse,
    Rotated,
    Seeded(u64),
}

impl Schedule {
    fn permutation(self, job_count: usize) -> Vec<usize> {
        let mut ordinals = (0..job_count).collect::<Vec<_>>();
        match self {
            Self::Serial => {}
            Self::Reverse => ordinals.reverse(),
            Self::Rotated if job_count > 1 => {
                let offset = (job_count / 3).max(1);
                ordinals.rotate_left(offset);
            }
            Self::Rotated => {}
            Self::Seeded(seed) => seeded_permutation(&mut ordinals, seed),
        }
        ordinals
    }
}

struct ScheduledExecutor(Schedule);

impl DisclosureVerificationExecutor for ScheduledExecutor {
    fn execute<'a>(
        &self,
        jobs: &[DisclosureVerificationJob<'a>],
    ) -> Result<Vec<DisclosureVerificationOutcome<'a>>> {
        Ok(self
            .0
            .permutation(jobs.len())
            .into_iter()
            .map(|ordinal| jobs[ordinal].process())
            .collect())
    }
}

struct InjectedFailureExecutor {
    fail_after: usize,
    processed: Cell<usize>,
}

impl DisclosureVerificationExecutor for InjectedFailureExecutor {
    fn execute<'a>(
        &self,
        jobs: &[DisclosureVerificationJob<'a>],
    ) -> Result<Vec<DisclosureVerificationOutcome<'a>>> {
        let mut partial = Vec::with_capacity(jobs.len());
        for job in jobs {
            if partial.len() == self.fail_after {
                self.processed.set(partial.len());
                return Err(Error::InvalidState(GENERIC_EXECUTOR_FAILURE.to_owned()));
            }
            partial.push(job.process());
        }
        self.processed.set(partial.len());
        Err(Error::InvalidState(GENERIC_EXECUTOR_FAILURE.to_owned()))
    }
}

fn seeded_permutation(ordinals: &mut [usize], mut state: u64) {
    for upper in (1..ordinals.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let selected = (state % (upper as u64 + 1)) as usize;
        ordinals.swap(upper, selected);
    }
}

fn schedules() -> [Schedule; 4] {
    [
        Schedule::Serial,
        Schedule::Reverse,
        Schedule::Rotated,
        Schedule::Seeded(SEEDED_SCHEDULE),
    ]
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn credentials(storage: &[Vec<String>]) -> Vec<CredentialDisclosures<'_>> {
    storage
        .iter()
        .map(|disclosures| CredentialDisclosures::new(disclosures))
        .collect()
}

fn populated_batch(batch_size: usize) -> Vec<Vec<String>> {
    (0..batch_size)
        .map(|credential_ordinal| match credential_ordinal % 4 {
            0 => owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]),
            1 => owned(&[ARRAY_DISCLOSURE]),
            2 => owned(&[OBJECT_DISCLOSURE]),
            _ => owned(&[ARRAY_DISCLOSURE, OBJECT_DISCLOSURE]),
        })
        .collect()
}

fn assert_mapping_schedule_independence(storage: &[Vec<String>]) {
    let inputs = credentials(storage);
    let expected = preprocess_disclosure_verification_batch(&inputs).unwrap();

    for schedule in schedules() {
        let actual = preprocess_disclosure_verification_batch_with_executor(
            &inputs,
            &ScheduledExecutor(schedule),
        )
        .unwrap();
        assert_eq!(actual, expected, "mapping changed under {schedule:?}");
    }
}

fn assert_error_schedule_independence(
    storage: &[Vec<String>],
    required_fragment: &str,
    forbidden_fragment: &str,
) {
    let inputs = credentials(storage);
    let expected = preprocess_disclosure_verification_batch(&inputs).unwrap_err();
    let expected_message = expected.to_string();
    let expected_discriminant = std::mem::discriminant(&expected);

    assert!(expected_message.contains(required_fragment));
    assert!(!expected_message.contains(forbidden_fragment));

    for schedule in schedules() {
        let actual = preprocess_disclosure_verification_batch_with_executor(
            &inputs,
            &ScheduledExecutor(schedule),
        )
        .unwrap_err();
        assert_eq!(
            std::mem::discriminant(&actual),
            expected_discriminant,
            "error variant changed under {schedule:?}"
        );
        assert_eq!(
            actual.to_string(),
            expected_message,
            "error message changed under {schedule:?}"
        );
    }
}

#[test]
fn formal_batch_sizes_have_exact_schedule_independent_mappings() {
    for batch_size in [1, 8, 32, 256] {
        let storage = populated_batch(batch_size);
        assert_mapping_schedule_independence(&storage);
    }
}

#[test]
fn seeded_job_permutation_is_stable_and_complete() {
    let first = Schedule::Seeded(SEEDED_SCHEDULE).permutation(32);
    let second = Schedule::Seeded(SEEDED_SCHEDULE).permutation(32);
    let mut sorted = first.clone();
    sorted.sort_unstable();

    assert_eq!(first, second);
    assert_eq!(
        first,
        [
            27, 12, 18, 1, 28, 7, 11, 23, 24, 22, 6, 9, 14, 25, 2, 8, 10, 5, 4, 30, 17, 15, 26, 19,
            29, 3, 21, 16, 31, 0, 20, 13,
        ]
    );
    assert_eq!(sorted, (0..32).collect::<Vec<_>>());
}

#[test]
fn empty_and_populated_credentials_keep_exact_caller_positions_under_every_schedule() {
    let storage = vec![
        Vec::new(),
        owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]),
        Vec::new(),
        owned(&[ARRAY_DISCLOSURE]),
    ];
    assert_mapping_schedule_independence(&storage);

    let inputs = credentials(&storage);
    let mappings = preprocess_disclosure_verification_batch(&inputs).unwrap();
    assert_eq!(
        mappings
            .iter()
            .map(|mapping| (
                mapping.credential_id().ordinal(),
                mapping.ordered_digests().len()
            ))
            .collect::<Vec<_>>(),
        [(0, 0), (1, 2), (2, 0), (3, 1)]
    );
}

#[test]
fn error_precedence_is_credential_ordinal_then_local_disclosure_ordinal() {
    let lower_credential_json_error = vec![
        Vec::new(),
        owned(&[OBJECT_DISCLOSURE]),
        owned(&[
            ARRAY_DISCLOSURE,
            INVALID_JSON_DISCLOSURE,
            INVALID_BASE64_DISCLOSURE,
        ]),
        owned(&[INVALID_BASE64_DISCLOSURE]),
    ];
    assert_error_schedule_independence(
        &lower_credential_json_error,
        "Error parsing disclosure ew",
        "Error decoding disclosure %",
    );

    let lower_local_base64_error = vec![
        Vec::new(),
        owned(&[OBJECT_DISCLOSURE]),
        owned(&[
            ARRAY_DISCLOSURE,
            INVALID_BASE64_DISCLOSURE,
            INVALID_JSON_DISCLOSURE,
        ]),
        owned(&[INVALID_JSON_DISCLOSURE]),
    ];
    assert_error_schedule_independence(
        &lower_local_base64_error,
        "Error decoding disclosure %",
        "Error parsing disclosure ew",
    );
}

#[test]
fn repeated_digest_is_credential_local_under_every_schedule() {
    let repeated_across_credentials = vec![
        owned(&[OBJECT_DISCLOSURE]),
        owned(&[OBJECT_DISCLOSURE]),
        owned(&[ARRAY_DISCLOSURE]),
    ];
    assert_mapping_schedule_independence(&repeated_across_credentials);

    let inputs = credentials(&repeated_across_credentials);
    let mappings = preprocess_disclosure_verification_batch(&inputs).unwrap();
    assert_eq!(
        mappings[0].ordered_digests()[0],
        mappings[1].ordered_digests()[0]
    );

    let duplicate_within_one = vec![
        owned(&[OBJECT_DISCLOSURE]),
        owned(&[OBJECT_DISCLOSURE, OBJECT_DISCLOSURE]),
        owned(&[INVALID_BASE64_DISCLOSURE]),
    ];
    let duplicate_inputs = credentials(&duplicate_within_one);
    let expected = preprocess_disclosure_verification_batch(&duplicate_inputs).unwrap_err();
    assert!(matches!(&expected, Error::DuplicateDigestError(_)));
    let expected_message = expected.to_string();

    for schedule in schedules() {
        let actual = preprocess_disclosure_verification_batch_with_executor(
            &duplicate_inputs,
            &ScheduledExecutor(schedule),
        )
        .unwrap_err();
        assert!(matches!(&actual, Error::DuplicateDigestError(_)));
        assert_eq!(actual.to_string(), expected_message);
        assert!(!actual.to_string().contains(INVALID_BASE64_DISCLOSURE));
    }
}

#[test]
fn injected_executor_failure_is_generic_redacted_and_publishes_no_partial_mapping() {
    let storage = vec![
        owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]),
        owned(&[ARRAY_DISCLOSURE, OBJECT_DISCLOSURE]),
    ];
    let inputs = credentials(&storage);
    let executor = InjectedFailureExecutor {
        fail_after: 2,
        processed: Cell::new(0),
    };

    let error = match preprocess_disclosure_verification_batch_with_executor(&inputs, &executor) {
        Ok(_) => panic!("an executor failure must not publish partial mappings"),
        Err(error) => error,
    };

    assert_eq!(executor.processed.get(), 2);
    assert_eq!(
        error.to_string(),
        format!("invalid state: {GENERIC_EXECUTOR_FAILURE}")
    );
    assert_eq!(
        format!("{error:?}"),
        format!("InvalidState(\"{GENERIC_EXECUTOR_FAILURE}\")")
    );
    for sensitive in [OBJECT_DISCLOSURE, ARRAY_DISCLOSURE, "Alice"] {
        assert!(!error.to_string().contains(sensitive));
        assert!(!format!("{error:?}").contains(sensitive));
    }
}
