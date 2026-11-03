//! Fixed-window physical-send admission. The caller owns the effect transaction
//! and its existing runtime guard; this module never commits or calls a provider.
use super::state::Start;
use crate::{
    credentials::crypto::{Provider, validate_account},
    email::Purpose,
    local,
    native_codec::{decimal, optional_decimal, uuid_text},
    native_slice::{Error, Result},
    storage::{ReadTransaction, ReadableTable, TableDefinition, WriteTransaction},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, ops::Bound};
use uuid::Uuid;

pub const FORMAT: &str = "email-rate-admission-1";
pub const MAX_POLICIES: usize = 16;
pub const MAX_STARTS: usize = 768;
pub const MAX_WINDOW_MS: i64 = 86_400_000;
pub const MAX_LIMIT: u16 = 64;
pub const MAX_DISPATCH_AGE_MS: i64 = 1_000;
type Definition = TableDefinition<'static, &'static [u8], &'static [u8]>;
pub(crate) const SCOPES: Definition = TableDefinition::new("email_rate_scopes");
pub(crate) const STARTS: Definition = TableDefinition::new("email_rate_starts");
pub(crate) const POINTS: Definition = TableDefinition::new("email_rate_points");
pub(crate) const TABLES: [(Definition, usize); 3] = [
    (SCOPES, MAX_POLICIES),
    (STARTS, MAX_STARTS),
    (POINTS, MAX_STARTS),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaScope {
    pub provider: Provider,
    pub account: String,
    pub purpose: Purpose,
}
impl QuotaScope {
    fn validate(&self) -> Result<()> {
        validate_account(&self.account).map_err(|_| configuration())?;
        if (self.provider == Provider::FakeSms) != (self.purpose == Purpose::SmsSend) {
            return Err(configuration());
        }
        Ok(())
    }
    fn key(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"next-base/email-rate-scope/1\0");
        hash.update(local::encode(self)?);
        Ok(hash.finalize().to_vec())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub provider: Provider,
    pub account: String,
    pub purpose: Purpose,
    #[serde(with = "decimal")]
    pub window_ms: i64,
    pub limit: u16,
}
impl Policy {
    pub fn scope(&self) -> QuotaScope {
        QuotaScope {
            provider: self.provider,
            account: self.account.clone(),
            purpose: self.purpose,
        }
    }
    fn validate(&self) -> Result<()> {
        self.scope().validate()?;
        if !(1..=MAX_WINDOW_MS).contains(&self.window_ms) || !(1..=MAX_LIMIT).contains(&self.limit)
        {
            return Err(configuration());
        }
        Ok(())
    }
}

/// Constructed once from operator configuration, never from an email request.
#[derive(Clone, Debug, Default)]
pub struct Policies(BTreeMap<Vec<u8>, Policy>);
impl Policies {
    pub fn new(policies: Vec<Policy>) -> Result<Self> {
        if policies.len() > MAX_POLICIES {
            return Err(configuration());
        }
        let mut result = BTreeMap::new();
        for policy in policies {
            policy.validate()?;
            if result.insert(policy.scope().key()?, policy).is_some() {
                return Err(configuration());
            }
        }
        Ok(Self(result))
    }
    pub fn get(&self, scope: &QuotaScope) -> Result<&Policy> {
        self.0.get(&scope.key()?).ok_or_else(configuration)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: String,
    policy: Policy,
    #[serde(with = "optional_decimal")]
    last_at: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Charge {
    format: String,
    scope: QuotaScope,
    #[serde(with = "uuid_text")]
    execution: Uuid,
    start: Start,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Admitted { added_bytes: u64 },
    RetryAt(i64),
}

/// Construct these from immutable execution bindings and retained start history,
/// not from this module's charge rows, count caches or range-query output.
#[derive(Clone, Debug)]
pub(crate) struct ExpectedStart {
    pub scope: QuotaScope,
    pub execution: Uuid,
    pub start: Start,
}

fn configuration() -> Error {
    Error::new(
        "rate_configuration",
        "email quota configuration does not match",
    )
}
fn ensure(condition: bool, detail: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(local::corrupt(detail))
    }
}
fn validate_start(execution: Uuid, start: &Start) -> Result<()> {
    ensure(
        !execution.is_nil()
            && !start.activation.is_nil()
            && !start.token.is_nil()
            && start.at >= 0
            && (1..=super::state::MAX_ATTEMPTS).contains(&start.attempt),
        "email admission start identity",
    )
}
fn start_key(execution: Uuid, attempt: u8) -> Vec<u8> {
    [execution.as_bytes().as_slice(), &[attempt]].concat()
}
fn point_key(scope: &[u8], execution: Uuid, start: &Start) -> Vec<u8> {
    [
        scope,
        start.at.to_be_bytes().as_slice(),
        execution.as_bytes().as_slice(),
        &[start.attempt],
    ]
    .concat()
}
fn time_key(scope: &[u8], at: i64, high: bool) -> Vec<u8> {
    [
        scope,
        at.to_be_bytes().as_slice(),
        &[if high { 255 } else { 0 }; 17],
    ]
    .concat()
}
fn checked_bytes(key: &[u8], value: &[u8]) -> Result<u64> {
    u64::try_from(
        key.len()
            .checked_add(value.len())
            .ok_or_else(|| Error::new("overflow", "email admission bytes"))?,
    )
    .map_err(|_| Error::new("overflow", "email admission bytes"))
}
fn header(key: &[u8], bytes: &[u8]) -> Result<Header> {
    let row: Header = local::decode(bytes)?;
    row.policy
        .validate()
        .map_err(|_| local::corrupt("email admission policy"))?;
    ensure(
        row.format == FORMAT
            && row.policy.scope().key()? == key
            && row.last_at.is_none_or(|at| at >= 0),
        "email admission scope identity",
    )?;
    Ok(row)
}
fn charge(key: &[u8], bytes: &[u8]) -> Result<Charge> {
    let row: Charge = local::decode(bytes)?;
    row.scope
        .validate()
        .map_err(|_| local::corrupt("email admission scope"))?;
    validate_start(row.execution, &row.start)?;
    ensure(
        row.format == FORMAT && start_key(row.execution, row.start.attempt) == key,
        "email admission charge identity",
    )?;
    Ok(row)
}

/// Initialize configured scopes and reject changed or omitted persisted policy.
/// Returns bytes added to the caller's bounded effect runtime accounting.
pub(crate) fn configure(write: &WriteTransaction, policies: &Policies) -> Result<u64> {
    let mut table = write.open_table(SCOPES)?;
    let mut present = BTreeMap::new();
    for (position, row) in table.iter()?.enumerate() {
        ensure(position < MAX_POLICIES, "email admission policy inventory")?;
        let (key, bytes) = row?;
        let row = header(key.value(), bytes.value())?;
        if policies.0.get(key.value()) != Some(&row.policy) {
            return Err(configuration());
        }
        present.insert(key.value().to_vec(), ());
    }
    let mut added = 0;
    for (key, policy) in &policies.0 {
        if present.contains_key(key) {
            continue;
        }
        let bytes = local::encode(&Header {
            format: FORMAT.into(),
            policy: policy.clone(),
            last_at: None,
        })?;
        table.insert(key.as_slice(), bytes.as_slice())?;
        added += checked_bytes(key, &bytes)?;
    }
    Ok(added)
}

/// Stage one physical start alongside the caller's execution marker and history.
/// Caller guarantees at most MAX_RETAINED executions, owns the existing protected
/// effect-runtime guard, accounts returned bytes, and aborts on any error. Three
/// unique starts per retained execution imply MAX_STARTS without a global count.
pub(crate) fn admit(
    write: &WriteTransaction,
    policies: &Policies,
    scope: &QuotaScope,
    execution: Uuid,
    start: &Start,
) -> Result<Decision> {
    validate_start(execution, start)?;
    let policy = policies.get(scope)?;
    let scope_key = scope.key()?;
    let mut scope_table = write.open_table(SCOPES)?;
    let old = scope_table
        .get(scope_key.as_slice())?
        .ok_or_else(configuration)?;
    let mut row = header(&scope_key, old.value())?;
    if row.policy != *policy {
        return Err(configuration());
    }
    let mut starts = write.open_table(STARTS)?;
    let mut points = write.open_table(POINTS)?;
    let identity = start_key(execution, start.attempt);
    let ordered = point_key(&scope_key, execution, start);
    let expected = Charge {
        format: FORMAT.into(),
        scope: scope.clone(),
        execution,
        start: start.clone(),
    };
    if let Some(bytes) = starts.get(identity.as_slice())? {
        ensure(
            charge(&identity, bytes.value())? == expected,
            "email admission token reuse",
        )?;
        ensure(
            points
                .get(ordered.as_slice())?
                .is_some_and(|v| v.value().is_empty())
                && row.last_at.is_some_and(|at| at >= start.at),
            "email admission recovery point",
        )?;
        return Ok(Decision::Admitted { added_bytes: 0 });
    }
    if row.last_at.is_some_and(|at| start.at < at) {
        return Err(Error::new("rate_clock", "email admission clock regressed"));
    }
    if start.attempt > 1 {
        let prior_key = start_key(execution, start.attempt - 1);
        let prior = starts
            .get(prior_key.as_slice())?
            .ok_or_else(|| local::corrupt("email admission start history gap"))?;
        let prior = charge(&prior_key, prior.value())?;
        ensure(
            prior.scope == *scope && prior.start.at <= start.at,
            "email admission changed execution scope/time",
        )?;
    }
    // At nonnegative admitted times, a negative lower boundary includes all
    // existing points. Otherwise exclude the COMPLETE equal-time lower group.
    let lower_at = start
        .at
        .checked_sub(policy.window_ms)
        .ok_or_else(|| Error::new("overflow", "email admission time"))?;
    let lower_key = time_key(&scope_key, lower_at.max(0), lower_at >= 0);
    let lower = if lower_at < 0 {
        Bound::Included(lower_key.as_slice())
    } else {
        Bound::Excluded(lower_key.as_slice())
    };
    let upper_key = time_key(&scope_key, start.at, true);
    let mut active = 0;
    let mut oldest = None;
    for item in points.range::<&[u8]>((lower, Bound::Included(upper_key.as_slice())))? {
        let (key, value) = item?;
        ensure(
            key.value().len() == 57 && value.value().is_empty(),
            "email admission point",
        )?;
        let at = i64::from_be_bytes(
            key.value()[32..40]
                .try_into()
                .expect("checked point length"),
        );
        ensure(at >= 0 && at <= start.at, "email admission point time")?;
        oldest.get_or_insert(at);
        active += 1;
        if active >= policy.limit {
            let retry = oldest
                .expect("nonempty active window")
                .checked_add(policy.window_ms)
                .ok_or_else(|| Error::new("overflow", "email admission retry time"))?;
            return Ok(Decision::RetryAt(retry));
        }
    }
    ensure(
        points.get(ordered.as_slice())?.is_none(),
        "email admission orphan point",
    )?;
    let bytes = local::encode(&expected)?;
    row.last_at = Some(start.at);
    let updated = local::encode(&row)?;
    let added_bytes = checked_bytes(&identity, &bytes)?
        .checked_add(checked_bytes(&ordered, &[])?)
        .and_then(|n| {
            n.checked_add(updated.len() as u64)?
                .checked_sub(old.value().len() as u64)
        })
        .ok_or_else(|| Error::new("overflow", "email admission bytes"))?;
    starts.insert(identity.as_slice(), bytes.as_slice())?;
    points.insert(ordered.as_slice(), &[])?;
    scope_table.insert(scope_key.as_slice(), updated.as_slice())?;
    Ok(Decision::Admitted { added_bytes })
}

/// Exact durable-charge confirmation for start-ACK recovery and dispatch. This
/// does not authorize HTTP; the worker must also confirm its own current lease.
pub(crate) fn confirm(
    read: &ReadTransaction,
    scope: &QuotaScope,
    execution: Uuid,
    start: &Start,
) -> Result<()> {
    validate_start(execution, start)?;
    let key = start_key(execution, start.attempt);
    let table = read.open_table(STARTS)?;
    let bytes = table
        .get(key.as_slice())?
        .ok_or_else(|| local::corrupt("missing email charge"))?;
    let row = charge(&key, bytes.value())?;
    ensure(
        row.scope == *scope && row.start == *start,
        "email admission confirmation",
    )?;
    let scope_key = scope.key()?;
    let headers = read.open_table(SCOPES)?;
    let bytes = headers
        .get(scope_key.as_slice())?
        .ok_or_else(|| local::corrupt("missing email policy"))?;
    let row = header(&scope_key, bytes.value())?;
    ensure(
        row.last_at.is_some_and(|at| at >= start.at),
        "email admission confirmation time",
    )?;
    ensure(
        read.open_table(POINTS)?
            .get(point_key(&scope_key, execution, start))?
            .is_some_and(|v| v.value().is_empty()),
        "missing email admission point",
    )
}

/// Full bounded source-derived check. Independently count complete timestamp
/// groups from retained execution starts instead of using the admission reader.
pub(crate) fn check(read: &ReadTransaction, expected: &[ExpectedStart]) -> Result<u64> {
    ensure(
        expected.len() <= MAX_STARTS,
        "email admission history bound",
    )?;
    let mut headers = BTreeMap::new();
    let mut bytes_total = 0;
    for (position, item) in read.open_table(SCOPES)?.iter()?.enumerate() {
        ensure(position < MAX_POLICIES, "email admission policy inventory")?;
        let (key, bytes) = item?;
        let row = header(key.value(), bytes.value())?;
        bytes_total += checked_bytes(key.value(), bytes.value())?;
        headers.insert(key.value().to_vec(), row);
    }
    let mut wanted_starts = BTreeMap::new();
    let mut wanted_points = BTreeMap::new();
    let mut groups: BTreeMap<Vec<u8>, Vec<i64>> = BTreeMap::new();
    let mut executions: BTreeMap<Uuid, Vec<(u8, i64, Vec<u8>)>> = BTreeMap::new();
    for expected in expected {
        validate_start(expected.execution, &expected.start)?;
        let scope_key = expected.scope.key()?;
        ensure(
            headers.contains_key(&scope_key),
            "email start without policy",
        )?;
        let key = start_key(expected.execution, expected.start.attempt);
        let bytes = local::encode(&Charge {
            format: FORMAT.into(),
            scope: expected.scope.clone(),
            execution: expected.execution,
            start: expected.start.clone(),
        })?;
        ensure(
            wanted_starts.insert(key, bytes).is_none(),
            "duplicate email physical start",
        )?;
        wanted_points.insert(
            point_key(&scope_key, expected.execution, &expected.start),
            Vec::new(),
        );
        groups
            .entry(scope_key.clone())
            .or_default()
            .push(expected.start.at);
        executions.entry(expected.execution).or_default().push((
            expected.start.attempt,
            expected.start.at,
            scope_key,
        ));
    }
    ensure(
        executions.len() <= super::MAX_RETAINED as usize,
        "email execution retention bound",
    )?;
    for attempts in executions.values_mut() {
        attempts.sort();
        for (index, (attempt, at, scope)) in attempts.iter().enumerate() {
            ensure(
                usize::from(*attempt) == index + 1,
                "email start history gap",
            )?;
            if index > 0 {
                ensure(
                    *at >= attempts[index - 1].1 && *scope == attempts[index - 1].2,
                    "email start history scope/time",
                )?;
            }
        }
    }
    for (key, row) in headers {
        let times = groups.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        ensure(
            row.last_at == times.iter().copied().max(),
            "email policy clock differs from starts",
        )?;
        for &at in times {
            let count = times
                .iter()
                .filter(|&&s| {
                    i128::from(at) - i128::from(row.policy.window_ms) < i128::from(s) && s <= at
                })
                .count();
            ensure(
                count <= usize::from(row.policy.limit),
                "email quota exceeded by source starts",
            )?;
        }
    }
    for (definition, wanted) in [(STARTS, wanted_starts), (POINTS, wanted_points)] {
        let mut actual = BTreeMap::new();
        for (position, item) in read.open_table(definition)?.iter()?.enumerate() {
            ensure(position < MAX_STARTS, "email admission row bound")?;
            let (key, bytes) = item?;
            bytes_total += checked_bytes(key.value(), bytes.value())?;
            actual.insert(key.value().to_vec(), bytes.value().to_vec());
        }
        ensure(
            actual == wanted,
            "email admission differs from execution start history",
        )?;
    }
    Ok(bytes_total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Database;
    use std::path::PathBuf;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }
    fn policy(window: i64, limit: u16) -> Policy {
        Policy {
            provider: Provider::Resend,
            account: "shared-account".into(),
            purpose: Purpose::EmailSend,
            window_ms: window,
            limit,
        }
    }
    fn start(at: i64, sequence: u128) -> Start {
        Start {
            activation: id(1),
            token: id(sequence + 1000),
            at,
            attempt: 1,
        }
    }

    // Literal source-time oracle, written independently of byte keys, scope
    // headers, storage rows and the production admission range implementation.
    fn oracle(times: &[i64], now: i64, window: i64, limit: usize) -> Option<i64> {
        let active: Vec<_> = times
            .iter()
            .copied()
            .filter(|&s| i128::from(now) - i128::from(window) < i128::from(s) && s <= now)
            .collect();
        if active.len() < limit {
            None
        } else {
            Some(active.into_iter().min().unwrap() + window)
        }
    }
    #[test]
    fn literal_oracle_counts_ties_and_expiry_without_source_edits() {
        assert_eq!(oracle(&[0, 9], 9, 10, 2), Some(10));
        assert_eq!(oracle(&[0, 9], 10, 10, 2), None);
        assert_eq!(oracle(&[9, 9], 9, 10, 2), Some(19));
        assert_eq!(oracle(&[9, 9], 19, 10, 2), None);
        // The historical backdated counterexample explains the monotone guard.
        assert_eq!(oracle(&[0, 9], 8, 10, 2), None);
        assert_eq!(oracle(&[0, 8, 9], 9, 10, 2), Some(10));
    }
    struct Fixture {
        db: Option<Database>,
        path: PathBuf,
    }
    impl Fixture {
        fn new(policies: &Policies) -> Self {
            let path = std::env::temp_dir().join(format!("email-rate-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            let db = Database::create(path.join("store.redb")).unwrap();
            let write = db.begin_write().unwrap();
            for (table, _) in TABLES {
                write.open_table(table).unwrap();
            }
            configure(&write, policies).unwrap();
            write.commit().unwrap();
            Self { db: Some(db), path }
        }
        fn db(&self) -> &Database {
            self.db.as_ref().unwrap()
        }
        fn image(&self) -> Vec<(String, Vec<crate::storage::Row>)> {
            let read = self.db().begin_read().unwrap();
            TABLES
                .into_iter()
                .map(|(table, _)| {
                    let rows = read
                        .open_table(table)
                        .unwrap()
                        .iter()
                        .unwrap()
                        .map(|item| {
                            let (key, value) = item.unwrap();
                            (key.value().to_vec(), value.value().to_vec())
                        })
                        .collect();
                    (table.name().into(), rows)
                })
                .collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.db.take());
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn storage_agrees_with_literal_oracle_for_ties_windows_and_account_partitions() {
        for (window, limit) in [(1, 1), (10, 2), (17, 4)] {
            let first = policy(window, limit);
            let mut second = first.clone();
            second.provider = Provider::Brevo;
            let policies = Policies::new(vec![first.clone(), second.clone()]).unwrap();
            let fixture = Fixture::new(&policies);
            let mut history = Vec::new();
            let mut times = [Vec::new(), Vec::new()];
            let initial = check(&fixture.db().begin_read().unwrap(), &[]).unwrap();
            let mut added = initial;
            for (index, now) in [0, 0, 1, 1, 2, 8, 9, 9, 10, 10, 11, 18, 19, 19, 27, 40]
                .into_iter()
                .enumerate()
            {
                for (partition, selected) in [&first, &second].into_iter().enumerate() {
                    let execution = id((2 * index + partition + 10) as u128);
                    let start = start(now, (2 * index + partition + 10) as u128);
                    let expected = oracle(&times[partition], now, window, usize::from(limit));
                    let write = fixture.db().begin_write().unwrap();
                    let decision =
                        admit(&write, &policies, &selected.scope(), execution, &start).unwrap();
                    match (expected, decision) {
                        (None, Decision::Admitted { added_bytes }) => {
                            added += added_bytes;
                            times[partition].push(now);
                            history.push(ExpectedStart {
                                scope: selected.scope(),
                                execution,
                                start,
                            });
                        }
                        (Some(expected), Decision::RetryAt(actual)) => assert_eq!(actual, expected),
                        other => panic!("oracle disagrees: {other:?}"),
                    }
                    write.commit().unwrap();
                    assert_eq!(
                        check(&fixture.db().begin_read().unwrap(), &history).unwrap(),
                        added
                    );
                }
            }
        }
    }

    #[test]
    fn original_start_recovery_is_free_but_changed_token_time_or_scope_rejects() {
        let first = policy(10, 2);
        let mut second = first.clone();
        second.account = "other".into();
        let policies = Policies::new(vec![first.clone(), second.clone()]).unwrap();
        let fixture = Fixture::new(&policies);
        let original = start(10, 20);
        let write = fixture.db().begin_write().unwrap();
        admit(&write, &policies, &first.scope(), id(20), &original).unwrap();
        write.commit().unwrap();
        let before = fixture.image();
        for changes in 0..4 {
            let write = fixture.db().begin_write().unwrap();
            let mut altered = original.clone();
            let mut scope = first.scope();
            match changes {
                1 => altered.token = id(500),
                2 => altered.at += 1,
                3 => scope = second.scope(),
                _ => {}
            }
            let result = admit(&write, &policies, &scope, id(20), &altered);
            if changes == 0 {
                assert_eq!(result.unwrap(), Decision::Admitted { added_bytes: 0 });
            } else {
                assert!(result.is_err());
            }
            drop(write);
            assert_eq!(fixture.image(), before);
        }
        confirm(
            &fixture.db().begin_read().unwrap(),
            &first.scope(),
            id(20),
            &original,
        )
        .unwrap();
        // An accepted start's charge survives activation/lease changes elsewhere.
        let mut newer = start(11, 21);
        newer.activation = id(999);
        let write = fixture.db().begin_write().unwrap();
        admit(&write, &policies, &first.scope(), id(21), &newer).unwrap();
        write.commit().unwrap();
        let write = fixture.db().begin_write().unwrap();
        assert_eq!(
            admit(&write, &policies, &first.scope(), id(22), &start(11, 22)).unwrap(),
            Decision::RetryAt(20)
        );
    }

    #[test]
    fn rollback_clock_policy_changes_and_missing_inventory_fail_closed() {
        let policy = policy(10, 2);
        let policies = Policies::new(vec![policy.clone()]).unwrap();
        let fixture = Fixture::new(&policies);
        let before = fixture.image();
        let write = fixture.db().begin_write().unwrap();
        admit(&write, &policies, &policy.scope(), id(20), &start(10, 20)).unwrap();
        drop(write);
        assert_eq!(
            fixture.image(),
            before,
            "dropped transaction retained admission"
        );
        let expected = ExpectedStart {
            scope: policy.scope(),
            execution: id(20),
            start: start(10, 20),
        };
        let write = fixture.db().begin_write().unwrap();
        admit(
            &write,
            &policies,
            &expected.scope,
            expected.execution,
            &expected.start,
        )
        .unwrap();
        write.commit().unwrap();
        let before = fixture.image();
        let write = fixture.db().begin_write().unwrap();
        assert_eq!(
            admit(&write, &policies, &policy.scope(), id(21), &start(9, 21))
                .unwrap_err()
                .code,
            "rate_clock"
        );
        drop(write);
        for altered in [
            Policy {
                window_ms: 11,
                ..policy.clone()
            },
            Policy {
                limit: 3,
                ..policy.clone()
            },
        ] {
            let write = fixture.db().begin_write().unwrap();
            assert!(configure(&write, &Policies::new(vec![altered]).unwrap()).is_err());
        }
        let write = fixture.db().begin_write().unwrap();
        assert!(configure(&write, &Policies::default()).is_err());
        drop(write);
        assert_eq!(fixture.image(), before);
        let read = fixture.db().begin_read().unwrap();
        assert!(check(&read, &[]).is_err(), "missing entire history passed");
        check(&read, std::slice::from_ref(&expected)).unwrap();
        drop(read);
        let write = fixture.db().begin_write().unwrap();
        write
            .open_table(POINTS)
            .unwrap()
            .remove(point_key(
                &expected.scope.key().unwrap(),
                expected.execution,
                &expected.start,
            ))
            .unwrap();
        write.commit().unwrap();
        assert!(check(&fixture.db().begin_read().unwrap(), &[expected]).is_err());
    }

    #[test]
    fn configured_bounds_and_retry_overflow_are_explicit() {
        for (window, limit) in [(0, 1), (MAX_WINDOW_MS + 1, 1), (1, 0), (1, MAX_LIMIT + 1)] {
            assert!(Policies::new(vec![policy(window, limit)]).is_err());
        }
        assert!(Policies::new(vec![policy(10, 1), policy(10, 1)]).is_err());
        let many = (0..=MAX_POLICIES)
            .map(|index| Policy {
                account: format!("account-{index}"),
                ..policy(10, 1)
            })
            .collect();
        assert!(Policies::new(many).is_err());
        let policy = policy(10, 1);
        let policies = Policies::new(vec![policy.clone()]).unwrap();
        let fixture = Fixture::new(&policies);
        let write = fixture.db().begin_write().unwrap();
        admit(
            &write,
            &policies,
            &policy.scope(),
            id(20),
            &start(i64::MAX, 20),
        )
        .unwrap();
        write.commit().unwrap();
        let write = fixture.db().begin_write().unwrap();
        assert_eq!(
            admit(
                &write,
                &policies,
                &policy.scope(),
                id(21),
                &start(i64::MAX, 21)
            )
            .unwrap_err()
            .code,
            "overflow"
        );
        assert!(admit(&write, &policies, &policy.scope(), id(21), &start(-1, 21)).is_err());
    }

    #[test]
    fn reopen_preserves_wasted_charge_clock_and_three_physical_attempt_history() {
        assert_eq!(
            MAX_STARTS,
            super::super::MAX_RETAINED as usize * super::super::state::MAX_ATTEMPTS as usize
        );
        let policy = policy(10, 1);
        let policies = Policies::new(vec![policy.clone()]).unwrap();
        let mut fixture = Fixture::new(&policies);
        let mut history = Vec::new();
        for attempt in 1..=3 {
            let mut physical = start(i64::from(attempt) * 10, u128::from(attempt));
            physical.attempt = attempt;
            // Different worker activations still consume one shared account quota.
            physical.activation = id(u128::from(attempt));
            let write = fixture.db().begin_write().unwrap();
            assert_eq!(configure(&write, &policies).unwrap(), 0);
            assert!(matches!(
                admit(&write, &policies, &policy.scope(), id(20), &physical).unwrap(),
                Decision::Admitted { .. }
            ));
            write.commit().unwrap();
            history.push(ExpectedStart {
                scope: policy.scope(),
                execution: id(20),
                start: physical,
            });
            // No remote completion is recorded. Reopening cannot refund the charge.
            drop(fixture.db.take());
            fixture.db = Some(Database::open(fixture.path.join("store.redb")).unwrap());
            check(&fixture.db().begin_read().unwrap(), &history).unwrap();
            let now = i64::from(attempt) * 10;
            let write = fixture.db().begin_write().unwrap();
            assert_eq!(
                admit(&write, &policies, &policy.scope(), id(21), &start(now, 99)).unwrap(),
                Decision::RetryAt(now + 10)
            );
        }
        let before = fixture.image();
        let write = fixture.db().begin_write().unwrap();
        let mut fourth = start(40, 40);
        fourth.attempt = 4;
        assert!(admit(&write, &policies, &policy.scope(), id(20), &fourth).is_err());
        let mut gap = start(40, 41);
        gap.attempt = 2;
        assert!(admit(&write, &policies, &policy.scope(), id(21), &gap).is_err());
        drop(write);
        assert_eq!(fixture.image(), before);
    }
}
