// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Immutable SD-JWT issuance planning and deterministic serial assembly.
//!
//! Planning consumes disclosure and decoy randomness in the legacy depth-first
//! order and assigns stable job and compact structural-location identities
//! before any disclosure is encoded. Assembly validates an authoritative job
//! registry, restores disclosures by ordinal, and rejects missing, duplicate,
//! swapped, or misplaced jobs before the issuer signs.

use serde_json::{json, Map, Value};

use super::{ClaimsForSelectiveDisclosureStrategy, IssuanceRandomSource, SDJWTIssuer};
use crate::disclosure::SDJWTDisclosure;
use crate::error::{Error, Result};
use crate::utils::base64_hash;
use crate::{SD_DIGESTS_KEY, SD_LIST_PREFIX};

type JobId = u64;
type LocationId = u64;

struct PlannedJob {
    job_id: JobId,
    location_id: LocationId,
    operation: PlannedJobOperation,
}

enum PlannedJobOperation {
    ObjectDisclosure {
        ordinal: usize,
        key: String,
        salt: String,
    },
    ArrayDisclosure {
        ordinal: usize,
        salt: String,
    },
    Decoy {
        salt: String,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PlannedJobKind {
    ObjectDisclosure,
    ArrayDisclosure,
    Decoy,
}

impl PlannedJobOperation {
    fn kind(&self) -> PlannedJobKind {
        match self {
            Self::ObjectDisclosure { .. } => PlannedJobKind::ObjectDisclosure,
            Self::ArrayDisclosure { .. } => PlannedJobKind::ArrayDisclosure,
            Self::Decoy { .. } => PlannedJobKind::Decoy,
        }
    }

    fn disclosure_ordinal(&self) -> Option<usize> {
        match self {
            Self::ObjectDisclosure { ordinal, .. } | Self::ArrayDisclosure { ordinal, .. } => {
                Some(*ordinal)
            }
            Self::Decoy { .. } => None,
        }
    }
}

struct PlannedValue {
    location_id: LocationId,
    kind: PlannedValueKind,
}

enum PlannedValueKind {
    Scalar(Value),
    Array(Vec<PlannedArrayEntry>),
    Object(PlannedObject),
}

enum PlannedArrayEntry {
    Visible(PlannedValue),
    Disclosed { value: PlannedValue, job_id: JobId },
}

enum PlannedObjectEntry {
    Visible { key: String, value: PlannedValue },
    Disclosed { value: PlannedValue, job_id: JobId },
}

struct PlannedObject {
    entries: Vec<PlannedObjectEntry>,
    decoy_job_ids: Vec<JobId>,
}

pub(super) struct IssuancePlan {
    root: PlannedValue,
    jobs: Vec<PlannedJob>,
    disclosure_job_ids: Vec<JobId>,
}

pub(super) struct IssuanceAssembly {
    pub(super) claims: Value,
    pub(super) disclosures: Vec<SDJWTDisclosure>,
}

impl IssuancePlan {
    pub(super) fn create<'a, R: IssuanceRandomSource>(
        claims: Value,
        strategy: ClaimsForSelectiveDisclosureStrategy<'a>,
        add_decoy_claims: bool,
        random_source: &mut R,
    ) -> Result<Self> {
        let mut planner = Planner {
            add_decoy_claims,
            next_location_id: 0,
            jobs: Vec::new(),
            disclosure_job_ids: Vec::new(),
        };
        let root_location_id = planner.allocate_location_id()?;
        let root = planner.plan_value(claims, strategy, root_location_id, random_source)?;

        Ok(Self {
            root,
            jobs: planner.jobs,
            disclosure_job_ids: planner.disclosure_job_ids,
        })
    }

    pub(super) fn execute_serial(self) -> Result<IssuanceAssembly> {
        let mut assembler = SerialAssembler::new(self.jobs, self.disclosure_job_ids)?;
        let claims = assembler.execute_value(self.root)?;
        assembler.finish(claims)
    }
}

struct Planner {
    add_decoy_claims: bool,
    next_location_id: LocationId,
    jobs: Vec<PlannedJob>,
    disclosure_job_ids: Vec<JobId>,
}

impl Planner {
    fn plan_value<'a, R: IssuanceRandomSource>(
        &mut self,
        value: Value,
        strategy: ClaimsForSelectiveDisclosureStrategy<'a>,
        location_id: LocationId,
        random_source: &mut R,
    ) -> Result<PlannedValue> {
        let kind = match value {
            Value::Array(values) => self.plan_array(values, strategy, random_source)?,
            Value::Object(values) => {
                self.plan_object(values, strategy, location_id, random_source)?
            }
            scalar => PlannedValueKind::Scalar(scalar),
        };
        Ok(PlannedValue { location_id, kind })
    }

    fn plan_array<'a, R: IssuanceRandomSource>(
        &mut self,
        values: Vec<Value>,
        strategy: ClaimsForSelectiveDisclosureStrategy<'a>,
        random_source: &mut R,
    ) -> Result<PlannedValueKind> {
        let mut entries = Vec::with_capacity(values.len());

        for (index, value) in values.into_iter().enumerate() {
            let strategy_key = format!("[{index}]");
            let location_id = self.allocate_location_id()?;
            let planned_value = self.plan_value(
                value,
                strategy.next_level(&strategy_key),
                location_id,
                random_source,
            )?;
            let entry = if strategy.sd_for_key(&strategy_key) {
                PlannedArrayEntry::Disclosed {
                    value: planned_value,
                    job_id: self.plan_array_disclosure(location_id, random_source)?,
                }
            } else {
                PlannedArrayEntry::Visible(planned_value)
            };
            entries.push(entry);
        }

        Ok(PlannedValueKind::Array(entries))
    }

    fn plan_object<'a, R: IssuanceRandomSource>(
        &mut self,
        values: Map<String, Value>,
        strategy: ClaimsForSelectiveDisclosureStrategy<'a>,
        location_id: LocationId,
        random_source: &mut R,
    ) -> Result<PlannedValueKind> {
        let mut entries = Vec::with_capacity(values.len());

        for (key, value) in values {
            let child_location_id = self.allocate_location_id()?;
            let planned_value = self.plan_value(
                value,
                strategy.next_level(&key),
                child_location_id,
                random_source,
            )?;
            let entry = if strategy.sd_for_key(&key) {
                PlannedObjectEntry::Disclosed {
                    value: planned_value,
                    job_id: self.plan_object_disclosure(child_location_id, key, random_source)?,
                }
            } else {
                PlannedObjectEntry::Visible {
                    key,
                    value: planned_value,
                }
            };
            entries.push(entry);
        }

        let decoy_job_ids = if self.add_decoy_claims {
            let count = random_source
                .decoy_count(SDJWTIssuer::DECOY_MIN_ELEMENTS..SDJWTIssuer::DECOY_MAX_ELEMENTS);
            let mut decoys = Vec::with_capacity(count as usize);
            for _ in 0..count {
                decoys.push(self.plan_decoy(location_id, random_source)?);
            }
            decoys
        } else {
            Vec::new()
        };

        Ok(PlannedValueKind::Object(PlannedObject {
            entries,
            decoy_job_ids,
        }))
    }

    fn plan_object_disclosure<R: IssuanceRandomSource>(
        &mut self,
        location_id: LocationId,
        key: String,
        random_source: &mut R,
    ) -> Result<JobId> {
        let ordinal = self.disclosure_job_ids.len();
        let job_id = self.allocate_job_id()?;
        let salt = random_source.disclosure_salt();
        self.jobs.push(PlannedJob {
            job_id,
            location_id,
            operation: PlannedJobOperation::ObjectDisclosure { ordinal, key, salt },
        });
        self.disclosure_job_ids.push(job_id);
        Ok(job_id)
    }

    fn plan_array_disclosure<R: IssuanceRandomSource>(
        &mut self,
        location_id: LocationId,
        random_source: &mut R,
    ) -> Result<JobId> {
        let ordinal = self.disclosure_job_ids.len();
        let job_id = self.allocate_job_id()?;
        let salt = random_source.disclosure_salt();
        self.jobs.push(PlannedJob {
            job_id,
            location_id,
            operation: PlannedJobOperation::ArrayDisclosure { ordinal, salt },
        });
        self.disclosure_job_ids.push(job_id);
        Ok(job_id)
    }

    fn plan_decoy<R: IssuanceRandomSource>(
        &mut self,
        location_id: LocationId,
        random_source: &mut R,
    ) -> Result<JobId> {
        let job_id = self.allocate_job_id()?;
        let salt = random_source.decoy_salt();
        self.jobs.push(PlannedJob {
            job_id,
            location_id,
            operation: PlannedJobOperation::Decoy { salt },
        });
        Ok(job_id)
    }

    fn allocate_job_id(&self) -> Result<JobId> {
        JobId::try_from(self.jobs.len()).map_err(|_| invalid_plan("issuance job identity overflow"))
    }

    fn allocate_location_id(&mut self) -> Result<LocationId> {
        let location_id = self.next_location_id;
        self.next_location_id = self
            .next_location_id
            .checked_add(1)
            .ok_or_else(|| invalid_plan("issuance location identity overflow"))?;
        Ok(location_id)
    }
}

struct SerialAssembler {
    disclosures: Vec<Option<SDJWTDisclosure>>,
    jobs: Vec<Option<PlannedJob>>,
    disclosure_job_ids: Vec<JobId>,
}

impl SerialAssembler {
    fn new(jobs: Vec<PlannedJob>, disclosure_job_ids: Vec<JobId>) -> Result<Self> {
        Self::validate_registry(&jobs, &disclosure_job_ids)?;
        Ok(Self {
            disclosures: std::iter::repeat_with(|| None)
                .take(disclosure_job_ids.len())
                .collect(),
            jobs: jobs.into_iter().map(Some).collect(),
            disclosure_job_ids,
        })
    }

    fn validate_registry(jobs: &[PlannedJob], disclosure_job_ids: &[JobId]) -> Result<()> {
        for (index, job) in jobs.iter().enumerate() {
            let expected_job_id = JobId::try_from(index)
                .map_err(|_| invalid_plan("issuance job registry exceeds identity capacity"))?;
            if job.job_id != expected_job_id {
                return Err(invalid_plan(
                    "a job descriptor identity does not match its registry index",
                ));
            }

            if let Some(ordinal) = job.operation.disclosure_ordinal() {
                let bound_job_id = disclosure_job_ids
                    .get(ordinal)
                    .ok_or_else(|| invalid_plan("a disclosure ordinal is out of bounds"))?;
                if *bound_job_id != job.job_id {
                    return Err(invalid_plan(
                        "a disclosure ordinal is bound to the wrong job identity",
                    ));
                }
            }
        }

        for (ordinal, job_id) in disclosure_job_ids.iter().copied().enumerate() {
            let index = usize::try_from(job_id)
                .map_err(|_| invalid_plan("a disclosure job identity exceeds platform capacity"))?;
            let job = jobs
                .get(index)
                .ok_or_else(|| invalid_plan("a disclosure job identity is out of bounds"))?;
            if job.operation.disclosure_ordinal() != Some(ordinal) {
                return Err(invalid_plan(
                    "a disclosure registry entry is bound to the wrong ordinal",
                ));
            }
        }

        Ok(())
    }

    fn execute_value(&mut self, value: PlannedValue) -> Result<Value> {
        let PlannedValue { location_id, kind } = value;
        match kind {
            PlannedValueKind::Scalar(value) => Ok(value),
            PlannedValueKind::Array(entries) => self.execute_array(entries),
            PlannedValueKind::Object(object) => self.execute_object(location_id, object),
        }
    }

    fn execute_array(&mut self, entries: Vec<PlannedArrayEntry>) -> Result<Value> {
        let mut claims = Vec::with_capacity(entries.len());

        for entry in entries {
            match entry {
                PlannedArrayEntry::Visible(value) => {
                    claims.push(self.execute_value(value)?);
                }
                PlannedArrayEntry::Disclosed { value, job_id } => {
                    let location_id = value.location_id;
                    let subtree = self.execute_value(value)?;
                    let operation =
                        self.take_job(job_id, location_id, PlannedJobKind::ArrayDisclosure)?;
                    let PlannedJobOperation::ArrayDisclosure { ordinal, salt } = operation else {
                        return Err(invalid_plan("an array entry references the wrong job kind"));
                    };
                    let disclosure = SDJWTDisclosure::new_with_salt(None, subtree, salt);
                    claims.push(json!({ SD_LIST_PREFIX: disclosure.hash }));
                    self.record_disclosure(job_id, ordinal, disclosure)?;
                }
            }
        }

        Ok(Value::Array(claims))
    }

    fn execute_object(&mut self, location_id: LocationId, object: PlannedObject) -> Result<Value> {
        let mut claims = Map::new();
        claims.insert(SD_DIGESTS_KEY.to_owned(), Value::Null);
        let mut digests = Vec::with_capacity(object.entries.len() + object.decoy_job_ids.len());

        for entry in object.entries {
            match entry {
                PlannedObjectEntry::Visible { key, value } => {
                    claims.insert(key, self.execute_value(value)?);
                }
                PlannedObjectEntry::Disclosed { value, job_id } => {
                    let child_location_id = value.location_id;
                    let subtree = self.execute_value(value)?;
                    let operation =
                        self.take_job(job_id, child_location_id, PlannedJobKind::ObjectDisclosure)?;
                    let PlannedJobOperation::ObjectDisclosure { ordinal, key, salt } = operation
                    else {
                        return Err(invalid_plan(
                            "an object entry references the wrong job kind",
                        ));
                    };
                    let disclosure = SDJWTDisclosure::new_with_salt(Some(key), subtree, salt);
                    digests.push(disclosure.hash.clone());
                    self.record_disclosure(job_id, ordinal, disclosure)?;
                }
            }
        }

        for job_id in object.decoy_job_ids {
            let operation = self.take_job(job_id, location_id, PlannedJobKind::Decoy)?;
            let PlannedJobOperation::Decoy { salt } = operation else {
                return Err(invalid_plan("a decoy entry references the wrong job kind"));
            };
            digests.push(base64_hash(salt.as_bytes()));
        }

        if digests.is_empty() {
            claims.shift_remove(SD_DIGESTS_KEY);
        } else {
            digests.sort();
            claims.insert(
                SD_DIGESTS_KEY.to_owned(),
                Value::Array(digests.into_iter().map(Value::String).collect()),
            );
        }

        Ok(Value::Object(claims))
    }

    fn take_job(
        &mut self,
        job_id: JobId,
        location_id: LocationId,
        expected_kind: PlannedJobKind,
    ) -> Result<PlannedJobOperation> {
        let index = usize::try_from(job_id)
            .map_err(|_| invalid_plan("an issuance job identity exceeds platform capacity"))?;
        let slot = self
            .jobs
            .get_mut(index)
            .ok_or_else(|| invalid_plan("an issuance job identity is out of bounds"))?;
        let job = slot
            .take()
            .ok_or_else(|| invalid_plan("an issuance job was executed more than once"))?;
        if job.job_id != job_id {
            return Err(invalid_plan("an issuance job returned the wrong identity"));
        }
        if job.location_id != location_id {
            return Err(invalid_plan(
                "an issuance job was restored at the wrong structural location",
            ));
        }
        if job.operation.kind() != expected_kind {
            return Err(invalid_plan("an issuance job has the wrong operation kind"));
        }
        Ok(job.operation)
    }

    fn record_disclosure(
        &mut self,
        job_id: JobId,
        ordinal: usize,
        disclosure: SDJWTDisclosure,
    ) -> Result<()> {
        if self.disclosure_job_ids.get(ordinal) != Some(&job_id) {
            return Err(invalid_plan(
                "a disclosure result is bound to the wrong job identity",
            ));
        }
        let slot = self
            .disclosures
            .get_mut(ordinal)
            .ok_or_else(|| invalid_plan("a disclosure ordinal is out of bounds"))?;
        if slot.is_some() {
            return Err(invalid_plan("a disclosure ordinal appears more than once"));
        }
        *slot = Some(disclosure);
        Ok(())
    }

    fn finish(self, claims: Value) -> Result<IssuanceAssembly> {
        if self.jobs.iter().any(Option::is_some) {
            return Err(invalid_plan("not every issuance job was executed"));
        }

        let disclosures = self
            .disclosures
            .into_iter()
            .map(|disclosure| {
                disclosure.ok_or_else(|| invalid_plan("a planned disclosure result is missing"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(IssuanceAssembly {
            claims,
            disclosures,
        })
    }
}

fn invalid_plan(message: &str) -> Error {
    Error::InvalidState(format!("invalid issuance plan: {message}"))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::ops::Range;

    use serde_json::json;

    use super::*;
    use crate::utils::base64url_decode;

    #[derive(Debug, Eq, PartialEq)]
    enum RandomEvent {
        Disclosure(String),
        DecoyCount(u32),
        DecoySalt(String),
    }

    struct RecordingRandomSource {
        next_disclosure_salt: usize,
        decoy_counts: VecDeque<u32>,
        next_decoy_salt: usize,
        events: Vec<RandomEvent>,
    }

    impl RecordingRandomSource {
        fn with_decoy_counts(counts: impl IntoIterator<Item = u32>) -> Self {
            Self {
                next_disclosure_salt: 0,
                decoy_counts: counts.into_iter().collect(),
                next_decoy_salt: 0,
                events: Vec::new(),
            }
        }
    }

    impl IssuanceRandomSource for RecordingRandomSource {
        fn disclosure_salt(&mut self) -> String {
            let salt = format!("disclosure-{}", self.next_disclosure_salt);
            self.next_disclosure_salt += 1;
            self.events.push(RandomEvent::Disclosure(salt.clone()));
            salt
        }

        fn decoy_count(&mut self, range: Range<u32>) -> u32 {
            let count = self
                .decoy_counts
                .pop_front()
                .expect("decoy-count tape must not be exhausted");
            assert!(range.contains(&count));
            self.events.push(RandomEvent::DecoyCount(count));
            count
        }

        fn decoy_salt(&mut self) -> String {
            let salt = format!("decoy-{}", self.next_decoy_salt);
            self.next_decoy_salt += 1;
            self.events.push(RandomEvent::DecoySalt(salt.clone()));
            salt
        }
    }

    fn two_disclosure_plan() -> IssuancePlan {
        let mut random_source = RecordingRandomSource::with_decoy_counts([]);
        IssuancePlan::create(
            json!({ "first": 1, "second": 2 }),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            false,
            &mut random_source,
        )
        .unwrap()
    }

    fn object_entries_mut(plan: &mut IssuancePlan) -> &mut [PlannedObjectEntry] {
        match &mut plan.root.kind {
            PlannedValueKind::Object(object) => &mut object.entries,
            _ => panic!("test plan root must be an object"),
        }
    }

    fn disclosed_job_id_mut(entry: &mut PlannedObjectEntry) -> &mut JobId {
        match entry {
            PlannedObjectEntry::Disclosed { job_id, .. } => job_id,
            PlannedObjectEntry::Visible { .. } => panic!("test entry must be disclosed"),
        }
    }

    fn disclosure_ordinal_mut(job: &mut PlannedJob) -> &mut usize {
        match &mut job.operation {
            PlannedJobOperation::ObjectDisclosure { ordinal, .. }
            | PlannedJobOperation::ArrayDisclosure { ordinal, .. } => ordinal,
            PlannedJobOperation::Decoy { .. } => panic!("test job must be a disclosure"),
        }
    }

    fn assert_invalid_plan(plan: IssuancePlan, expected_message: &str) {
        let error = match plan.execute_serial() {
            Ok(_) => panic!("corrupted issuance plan must fail closed"),
            Err(error) => error,
        };
        match error {
            Error::InvalidState(message) => assert_eq!(message, expected_message),
            other => panic!("unexpected error for corrupted issuance plan: {other:?}"),
        }
    }

    #[test]
    fn planning_assigns_disclosure_ids_and_randomness_in_depth_first_postorder() {
        let claims = json!({
            "profile": { "name": "Alice" },
            "roles": ["admin"]
        });
        let mut random_source = RecordingRandomSource::with_decoy_counts([]);

        let plan = IssuancePlan::create(
            claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            false,
            &mut random_source,
        )
        .unwrap();

        assert_eq!(plan.disclosure_job_ids, vec![0, 1, 2, 3]);
        assert_eq!(
            plan.jobs.iter().map(|job| job.job_id).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(
            random_source.events,
            vec![
                RandomEvent::Disclosure("disclosure-0".to_owned()),
                RandomEvent::Disclosure("disclosure-1".to_owned()),
                RandomEvent::Disclosure("disclosure-2".to_owned()),
                RandomEvent::Disclosure("disclosure-3".to_owned()),
            ]
        );

        let assembly = plan.execute_serial().unwrap();
        assert_eq!(assembly.disclosures.len(), 4);
        let decoded = assembly
            .disclosures
            .iter()
            .map(|disclosure| {
                serde_json::from_slice::<Value>(
                    &base64url_decode(&disclosure.raw_b64)
                        .expect("planned disclosure must be valid Base64url"),
                )
                .expect("planned disclosure must be valid JSON")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            decoded
                .iter()
                .map(|disclosure| disclosure[0].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "disclosure-0",
                "disclosure-1",
                "disclosure-2",
                "disclosure-3",
            ]
        );
        assert_eq!(decoded[0][1], "name");
        assert_eq!(decoded[1][1], "profile");
        assert_eq!(decoded[2][1], "admin");
        assert_eq!(decoded[3][1], "roles");
        assert_eq!(
            decoded[1][2][SD_DIGESTS_KEY][0],
            assembly.disclosures[0].hash
        );
        assert_eq!(
            decoded[3][2][0][SD_LIST_PREFIX],
            assembly.disclosures[2].hash
        );
    }

    #[test]
    fn planning_allocates_nested_decoys_before_parent_decoys() {
        let claims = json!({ "nested": { "value": 1 } });
        let mut random_source = RecordingRandomSource::with_decoy_counts([2, 3]);

        let plan = IssuancePlan::create(
            claims,
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            true,
            &mut random_source,
        )
        .unwrap();

        assert!(plan.disclosure_job_ids.is_empty());
        assert_eq!(plan.jobs.len(), 5);
        assert_eq!(
            random_source.events,
            vec![
                RandomEvent::DecoyCount(2),
                RandomEvent::DecoySalt("decoy-0".to_owned()),
                RandomEvent::DecoySalt("decoy-1".to_owned()),
                RandomEvent::DecoyCount(3),
                RandomEvent::DecoySalt("decoy-2".to_owned()),
                RandomEvent::DecoySalt("decoy-3".to_owned()),
                RandomEvent::DecoySalt("decoy-4".to_owned()),
            ]
        );

        let assembly = plan.execute_serial().unwrap();
        assert!(assembly.disclosures.is_empty());
        assert_eq!(
            assembly.claims["nested"][SD_DIGESTS_KEY]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(assembly.claims[SD_DIGESTS_KEY].as_array().unwrap().len(), 3);
    }

    #[test]
    fn serial_assembly_rejects_duplicate_job_identity() {
        let mut plan = two_disclosure_plan();
        plan.jobs[1].job_id = plan.jobs[0].job_id;

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a job descriptor identity does not match its registry index",
        );
    }

    #[test]
    fn serial_assembly_rejects_swapped_job_references() {
        let mut plan = two_disclosure_plan();
        let entries = object_entries_mut(&mut plan);
        let (first, second) = entries.split_at_mut(1);
        std::mem::swap(
            disclosed_job_id_mut(&mut first[0]),
            disclosed_job_id_mut(&mut second[0]),
        );

        assert_invalid_plan(
            plan,
            "invalid issuance plan: an issuance job was restored at the wrong structural location",
        );
    }

    #[test]
    fn serial_assembly_rejects_out_of_range_tree_job_identity() {
        let mut plan = two_disclosure_plan();
        let out_of_range_job_id = JobId::try_from(plan.jobs.len()).unwrap();
        *disclosed_job_id_mut(&mut object_entries_mut(&mut plan)[0]) = out_of_range_job_id;

        assert_invalid_plan(
            plan,
            "invalid issuance plan: an issuance job identity is out of bounds",
        );
    }

    #[test]
    fn serial_assembly_rejects_mismatched_descriptor_location() {
        let mut plan = two_disclosure_plan();
        plan.jobs[0].location_id = plan.jobs[1].location_id;

        assert_invalid_plan(
            plan,
            "invalid issuance plan: an issuance job was restored at the wrong structural location",
        );
    }

    #[test]
    fn serial_assembly_rejects_duplicate_disclosure_ordinal() {
        let mut plan = two_disclosure_plan();
        let first_ordinal = *disclosure_ordinal_mut(&mut plan.jobs[0]);
        *disclosure_ordinal_mut(&mut plan.jobs[1]) = first_ordinal;

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure ordinal is bound to the wrong job identity",
        );
    }

    #[test]
    fn serial_assembly_rejects_swapped_disclosure_ordinals() {
        let mut plan = two_disclosure_plan();
        let (first, second) = plan.jobs.split_at_mut(1);
        std::mem::swap(
            disclosure_ordinal_mut(&mut first[0]),
            disclosure_ordinal_mut(&mut second[0]),
        );

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure ordinal is bound to the wrong job identity",
        );
    }

    #[test]
    fn serial_assembly_rejects_swapped_disclosure_registry_entries() {
        let mut plan = two_disclosure_plan();
        plan.disclosure_job_ids.swap(0, 1);

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure ordinal is bound to the wrong job identity",
        );
    }

    #[test]
    fn serial_assembly_rejects_out_of_range_disclosure_ordinal() {
        let mut plan = two_disclosure_plan();
        *disclosure_ordinal_mut(&mut plan.jobs[0]) = plan.disclosure_job_ids.len();

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure ordinal is out of bounds",
        );
    }

    #[test]
    fn serial_assembly_rejects_out_of_range_disclosure_registry_identity() {
        let mut random_source = RecordingRandomSource::with_decoy_counts([]);
        let mut plan = IssuancePlan::create(
            json!({}),
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            false,
            &mut random_source,
        )
        .unwrap();
        plan.disclosure_job_ids.push(0);

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure job identity is out of bounds",
        );
    }

    #[test]
    fn serial_assembly_rejects_missing_job() {
        let mut plan = two_disclosure_plan();
        match &mut plan.root.kind {
            PlannedValueKind::Object(object) => {
                object.entries.pop();
            }
            _ => panic!("test plan root must be an object"),
        }

        assert_invalid_plan(
            plan,
            "invalid issuance plan: not every issuance job was executed",
        );
    }
}
