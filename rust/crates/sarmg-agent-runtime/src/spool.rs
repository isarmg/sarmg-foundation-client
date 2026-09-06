//! One current binary container: bounded opaque payload, identity binding, and checksum.
use crate::{BoundedBytes, ContractId, Error, RecordId, SpoolRecord};
use sarmg_agent_fs_safety::{
    AdvisoryLock, AtomicFile, EntryName, FileEntry, InventoryLimits, NoClobberPublish,
    PrivateDirectory,
};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_SPOOL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_SPOOL_ENTRIES: usize = 4096;
const MAGIC: &[u8] = b"SARMGSPOOL\x01";
const CONTAINER_OVERHEAD: usize = MAGIC.len() + 16 + 1 + 8 + 2 + 128 + 4 + 32;
/// Fixed, persisted quarantine categories; never an arbitrary message or path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineReason {
    Corrupt,
    IdentityMismatch,
}

const LOCK: &str = "spool.instance.lock";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpoolLimits {
    pub max_record_bytes: usize,
    pub max_entries: usize,
    /// Physical container bytes, including quarantined records and their metadata.
    pub max_bytes: u64,
}
impl SpoolLimits {
    pub fn validate(self) -> Result<(), Error> {
        if self.max_record_bytes == 0
            || self.max_record_bytes > MAX_RECORD_BYTES
            || self.max_entries == 0
            || self.max_entries > MAX_SPOOL_ENTRIES
            || self.max_bytes == 0
            || self.max_bytes > MAX_SPOOL_BYTES
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

pub struct Spool {
    directory: PrivateDirectory,
    limits: SpoolLimits,
    gate: Mutex<()>,
    _lock: AdvisoryLock,
}

impl Spool {
    /// Bounded, read-only inventory of the current namespace. Does not lock,
    /// clean up, validate payloads, or create a missing directory. Concurrent
    /// changes can return an error; this is not a transactional snapshot.
    pub fn inspect_existing(
        path: impl AsRef<Path>,
        limits: SpoolLimits,
    ) -> Result<crate::AgentHealth, Error> {
        limits.validate()?;
        let directory = PrivateDirectory::open_existing(path)?;
        inventory_health(&current_entries(&directory, limits)?, limits)
    }

    pub fn open(path: impl AsRef<Path>, limits: SpoolLimits) -> Result<Self, Error> {
        limits.validate()?;
        let directory = PrivateDirectory::create(path)?;
        Self::from_directory(directory, limits)
    }

    /// Take ownership of an already anchored private-directory capability.
    pub fn from_directory(directory: PrivateDirectory, limits: SpoolLimits) -> Result<Self, Error> {
        limits.validate()?;
        let lock = AdvisoryLock::acquire(&directory, &EntryName::new(LOCK)?.as_relative())
            .map_err(|error| {
                if matches!(error, sarmg_agent_fs_safety::Error::AlreadyLocked(_)) {
                    Error::AlreadyRunning
                } else {
                    Error::Filesystem(error)
                }
            })?;
        let spool = Self {
            directory,
            limits,
            gate: Mutex::new(()),
            _lock: lock,
        };
        // The process lock precedes cleanup. Only exact platform temporaries qualify;
        // no other live writer can own a temporary within this spool.
        let entries = spool.directory.files(InventoryLimits {
            max_entries: limits.max_entries + 2,
            max_total_bytes: limits
                .max_bytes
                .saturating_add((limits.max_record_bytes + CONTAINER_OVERHEAD) as u64),
        })?;
        for entry in entries {
            if AtomicFile::is_temporary_name(&entry.name) {
                spool.directory.remove_file(&entry.name)?;
            }
        }
        spool.entries()?;
        Ok(spool)
    }

    fn guard(&self) -> Result<MutexGuard<'_, ()>, Error> {
        self.gate.lock().map_err(|_| Error::SpoolUnavailable)
    }

    fn entries(&self) -> Result<Vec<FileEntry>, Error> {
        current_entries(&self.directory, self.limits)
    }

    pub fn enqueue(
        &self,
        contract_id: ContractId,
        created_at_micros: i64,
        payload: BoundedBytes,
    ) -> Result<RecordId, Error> {
        self.enqueue_with_priority(contract_id, created_at_micros, 100, payload)
    }

    pub fn enqueue_with_priority(
        &self,
        contract_id: ContractId,
        created_at_micros: i64,
        priority: u8,
        payload: BoundedBytes,
    ) -> Result<RecordId, Error> {
        let _guard = self.guard()?;
        if payload.0.len() > self.limits.max_record_bytes {
            return Err(Error::RecordTooLarge);
        }
        if created_at_micros < 0 {
            return Err(Error::InvalidRecord);
        }
        let id = RecordId::new()?;
        let record = SpoolRecord {
            record_id: id.clone(),
            contract_id,
            created_at_micros,
            payload,
        };
        let bytes = encode(&record, priority)?;
        let entries = self.entries()?;
        let used = entries
            .iter()
            .try_fold(0u64, |total, entry| total.checked_add(entry.bytes))
            .ok_or(Error::SpoolFull)?;
        if entries.len() >= self.limits.max_entries
            || used
                .checked_add(bytes.len() as u64)
                .is_none_or(|total| total > self.limits.max_bytes)
        {
            return Err(Error::SpoolFull);
        }
        AtomicFile::create(
            &self.directory,
            &record_name(priority, created_at_micros, &id, None)?,
            &bytes,
        )?;
        Ok(id)
    }

    pub fn next(&self) -> Result<Option<SpoolRecord>, Error> {
        let _guard = self.guard()?;
        for entry in self.entries()? {
            let name = parse_name(&entry.name)?;
            if name.quarantined.is_some() {
                continue;
            }
            let bytes = match self.directory.read_bounded(
                &entry.name,
                self.limits.max_record_bytes + CONTAINER_OVERHEAD,
            ) {
                Ok(bytes) => bytes,
                Err(sarmg_agent_fs_safety::Error::BudgetExceeded) => {
                    self.quarantine_entry(&entry.name, &name, QuarantineReason::Corrupt)?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            match decode(&bytes, &name, self.limits.max_record_bytes) {
                Ok(record) => return Ok(Some(record)),
                Err(Error::InvalidRecord | Error::InvalidContract | Error::RecordTooLarge) => {
                    self.quarantine_entry(&entry.name, &name, QuarantineReason::Corrupt)?
                }
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn quarantine_entry(
        &self,
        entry: &EntryName,
        name: &Name,
        reason: QuarantineReason,
    ) -> Result<(), Error> {
        let target = record_name(
            name.priority,
            name.created_at_micros,
            &name.id,
            Some(reason),
        )?;
        NoClobberPublish::publish(&self.directory, &entry.as_relative(), &target.as_relative())?;
        Ok(())
    }

    pub fn ack(&self, id: &RecordId) -> Result<(), Error> {
        let _guard = self.guard()?;
        let entry = self.find(id)?;
        self.directory.remove_file(&entry.name)?;
        Ok(())
    }

    pub fn quarantine(&self, id: &RecordId, reason: QuarantineReason) -> Result<(), Error> {
        let _guard = self.guard()?;
        let entry = self.find(id)?;
        self.quarantine_entry(&entry.name, &parse_name(&entry.name)?, reason)
    }

    fn find(&self, id: &RecordId) -> Result<FileEntry, Error> {
        let mut matches = self.entries()?.into_iter().filter(|entry| {
            parse_name(&entry.name).is_ok_and(|name| name.quarantined.is_none() && name.id == *id)
        });
        let entry = matches.next().ok_or(Error::RecordNotFound)?;
        if matches.next().is_some() {
            return Err(Error::InvalidRecord);
        }
        Ok(entry)
    }

    /// Pending count and total physical bytes (including retained quarantines).
    pub fn usage(&self) -> Result<(usize, u64), Error> {
        let _guard = self.guard()?;
        let entries = self.entries()?;
        let pending = entries
            .iter()
            .filter(|entry| parse_name(&entry.name).is_ok_and(|name| name.quarantined.is_none()))
            .count();
        Ok((pending, entries.iter().map(|entry| entry.bytes).sum()))
    }

    pub fn doctor(&self) -> Result<crate::AgentHealth, Error> {
        let _guard = self.guard()?;
        inventory_health(&self.entries()?, self.limits)
    }
}

fn current_entries(
    directory: &PrivateDirectory,
    limits: SpoolLimits,
) -> Result<Vec<FileEntry>, Error> {
    let mut entries = directory.files(InventoryLimits {
        max_entries: limits.max_entries + 1,
        max_total_bytes: limits.max_bytes,
    })?;
    for entry in &entries {
        if entry.name.as_os_str() == LOCK {
            if entry.bytes != 0 {
                return Err(Error::InvalidRecord);
            }
        } else {
            parse_name(&entry.name)?;
        }
    }
    entries.retain(|entry| entry.name.as_os_str() != LOCK);
    if entries.len() > limits.max_entries {
        return Err(Error::SpoolFull);
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn inventory_health(
    entries: &[FileEntry],
    limits: SpoolLimits,
) -> Result<crate::AgentHealth, Error> {
    let mut quarantined = 0;
    let mut identity_mismatch = 0;
    let mut bytes = 0u64;
    for entry in entries {
        let reason = parse_name(&entry.name)?.quarantined;
        quarantined += usize::from(reason.is_some());
        identity_mismatch += usize::from(reason == Some(QuarantineReason::IdentityMismatch));
        bytes = bytes.checked_add(entry.bytes).ok_or(Error::SpoolFull)?;
    }
    Ok(crate::AgentHealth {
        healthy: quarantined == 0,
        spool_entries: entries.len() - quarantined,
        spool_bytes: bytes,
        quarantined_entries: quarantined,
        identity_mismatch_entries: identity_mismatch,
        capacity_remaining: entries.len() < limits.max_entries && bytes < limits.max_bytes,
    })
}

struct Name {
    id: RecordId,
    priority: u8,
    created_at_micros: i64,
    quarantined: Option<QuarantineReason>,
}
fn record_name(
    priority: u8,
    created_at_micros: i64,
    id: &RecordId,
    quarantined: Option<QuarantineReason>,
) -> Result<EntryName, Error> {
    let extension = match quarantined {
        None => "record",
        Some(QuarantineReason::Corrupt) => "bad",
        Some(QuarantineReason::IdentityMismatch) => "identity",
    };
    Ok(EntryName::new(format!(
        "{priority:03}-{created_at_micros:020}-{}.{extension}",
        id.as_str()
    ))?)
}
fn parse_name(name: &EntryName) -> Result<Name, Error> {
    let text = name.as_os_str().to_str().ok_or(Error::InvalidRecord)?;
    let (stem, extension) = text.rsplit_once('.').ok_or(Error::InvalidRecord)?;
    let quarantined = match extension {
        "record" => None,
        "bad" => Some(QuarantineReason::Corrupt),
        "identity" => Some(QuarantineReason::IdentityMismatch),
        _ => return Err(Error::InvalidRecord),
    };
    let mut parts = stem.split('-');
    let priority = parts
        .next()
        .ok_or(Error::InvalidRecord)?
        .parse::<u8>()
        .map_err(|_| Error::InvalidRecord)?;
    let created_at_micros = parts
        .next()
        .ok_or(Error::InvalidRecord)?
        .parse::<i64>()
        .map_err(|_| Error::InvalidRecord)?;
    let id = RecordId::parse(parts.next().ok_or(Error::InvalidRecord)?.to_owned())?;
    if parts.next().is_some()
        || created_at_micros < 0
        || record_name(priority, created_at_micros, &id, quarantined)? != *name
    {
        return Err(Error::InvalidRecord);
    }
    Ok(Name {
        id,
        priority,
        created_at_micros,
        quarantined,
    })
}

fn encode(record: &SpoolRecord, priority: u8) -> Result<Vec<u8>, Error> {
    let mut bytes = MAGIC.to_vec();
    for part in record.record_id.as_str().as_bytes().as_chunks::<2>().0 {
        let value = std::str::from_utf8(part).map_err(|_| Error::InvalidRecord)?;
        bytes.push(u8::from_str_radix(value, 16).map_err(|_| Error::InvalidRecord)?);
    }
    bytes.push(priority);
    bytes.extend_from_slice(&record.created_at_micros.to_be_bytes());
    let contract = record.contract_id.0.as_bytes();
    bytes.extend_from_slice(&(contract.len() as u16).to_be_bytes());
    bytes.extend_from_slice(contract);
    bytes.extend_from_slice(
        &u32::try_from(record.payload.0.len())
            .map_err(|_| Error::RecordTooLarge)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&record.payload.0);
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    Ok(bytes)
}

fn decode(bytes: &[u8], name: &Name, max: usize) -> Result<SpoolRecord, Error> {
    let content_len = bytes.len().checked_sub(32).ok_or(Error::InvalidRecord)?;
    let (content, checksum) = bytes.split_at(content_len);
    if Sha256::digest(content).as_slice() != checksum {
        return Err(Error::InvalidRecord);
    }
    let mut remaining = content;
    fn take<'a>(input: &mut &'a [u8], size: usize) -> Result<&'a [u8], Error> {
        let (part, rest) = input.split_at_checked(size).ok_or(Error::InvalidRecord)?;
        *input = rest;
        Ok(part)
    }
    if take(&mut remaining, MAGIC.len())? != MAGIC {
        return Err(Error::InvalidRecord);
    }
    let id = RecordId::parse(
        take(&mut remaining, 16)?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )?;
    let priority = take(&mut remaining, 1)?[0];
    let created_at_micros = i64::from_be_bytes(
        take(&mut remaining, 8)?
            .try_into()
            .map_err(|_| Error::InvalidRecord)?,
    );
    let contract_len = u16::from_be_bytes(
        take(&mut remaining, 2)?
            .try_into()
            .map_err(|_| Error::InvalidRecord)?,
    ) as usize;
    if contract_len > 128 {
        return Err(Error::InvalidContract);
    }
    let contract_id = ContractId::new(
        std::str::from_utf8(take(&mut remaining, contract_len)?)
            .map_err(|_| Error::InvalidContract)?,
    )?;
    let payload_len = u32::from_be_bytes(
        take(&mut remaining, 4)?
            .try_into()
            .map_err(|_| Error::InvalidRecord)?,
    ) as usize;
    if payload_len > max
        || remaining.len() != payload_len
        || id != name.id
        || priority != name.priority
        || created_at_micros != name.created_at_micros
    {
        return Err(Error::InvalidRecord);
    }
    Ok(SpoolRecord {
        record_id: id,
        contract_id,
        created_at_micros,
        payload: BoundedBytes::new(remaining.to_vec(), max)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{Arc, Barrier},
    };

    fn limits() -> SpoolLimits {
        SpoolLimits {
            max_record_bytes: 1024,
            max_entries: 8,
            max_bytes: 16 * 1024,
        }
    }
    fn enqueue(spool: &Spool, time: i64, priority: u8, bytes: Vec<u8>) -> RecordId {
        spool
            .enqueue_with_priority(
                ContractId::new("example.current").unwrap(),
                time,
                priority,
                BoundedBytes::new(bytes, MAX_RECORD_BYTES).unwrap(),
            )
            .unwrap()
    }
    fn current_path(spool: &Spool) -> std::path::PathBuf {
        let entry = spool
            .entries()
            .unwrap()
            .into_iter()
            .find(|entry| {
                entry
                    .name
                    .as_path()
                    .extension()
                    .is_some_and(|value| value == "record")
            })
            .unwrap();
        spool.directory.path().join(entry.name.as_path())
    }

    #[test]
    fn inspection_is_read_only_and_works_while_the_writer_holds_its_lock() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        assert!(matches!(
            Spool::inspect_existing(&path, limits()),
            Err(Error::Filesystem(sarmg_agent_fs_safety::Error::Io(error)))
                if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(!path.exists());
        let spool = Spool::open(&path, limits()).unwrap();
        let first = enqueue(&spool, 1, 100, vec![1]);
        enqueue(&spool, 2, 100, vec![2]);
        spool.quarantine(&first, QuarantineReason::Corrupt).unwrap();
        let before = spool.entries().unwrap();
        let health = Spool::inspect_existing(&path, limits()).unwrap();
        assert_eq!(health.spool_entries, 1);
        assert_eq!(health.quarantined_entries, 1);
        assert!(!health.healthy);
        assert_eq!(
            health.spool_bytes,
            before.iter().map(|e| e.bytes).sum::<u64>()
        );
        assert_eq!(spool.entries().unwrap().len(), before.len());
        assert!(matches!(
            Spool::open(&path, limits()),
            Err(Error::AlreadyRunning)
        ));
        let temporary = path.join(".sarmg-atomic-0123456789abcdef0123456789abcdef.tmp");
        fs::write(&temporary, b"unfinished write").unwrap();
        assert!(Spool::inspect_existing(&path, limits()).is_err());
        assert_eq!(fs::read(&temporary).unwrap(), b"unfinished write");
    }

    #[test]
    fn inspection_enforces_record_budget_without_a_lock_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        let spool = Spool::open(&path, limits()).unwrap();
        enqueue(&spool, 1, 100, vec![1]);
        enqueue(&spool, 2, 100, vec![2]);
        drop(spool);
        fs::remove_file(path.join(LOCK)).unwrap();
        let mut constrained = limits();
        constrained.max_entries = 1;
        assert!(matches!(
            Spool::inspect_existing(&path, constrained),
            Err(Error::SpoolFull)
        ));
        assert!(!path.join(LOCK).exists());
    }

    #[cfg(unix)]
    #[test]
    fn inspection_rejects_links_without_changing_their_targets() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        let spool = Spool::open(&path, limits()).unwrap();
        enqueue(&spool, 1, 100, vec![1]);
        let record = current_path(&spool);
        let original = fs::read(&record).unwrap();
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(Spool::inspect_existing(&alias, limits()).is_err());
        fs::hard_link(&record, temp.path().join("outside-link")).unwrap();
        assert!(Spool::inspect_existing(&path, limits()).is_err());
        assert_eq!(fs::read(&record).unwrap(), original);
    }

    #[test]
    fn payload_is_stored_without_json_expansion_and_survives_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        let limits = SpoolLimits {
            max_record_bytes: MAX_RECORD_BYTES,
            max_entries: 2,
            max_bytes: 2 * MAX_RECORD_BYTES as u64,
        };
        let spool = Spool::open(&path, limits).unwrap();
        let id = enqueue(&spool, 12, 30, vec![255; MAX_RECORD_BYTES]);
        let size = fs::metadata(current_path(&spool)).unwrap().len();
        assert!(size <= (MAX_RECORD_BYTES + CONTAINER_OVERHEAD) as u64);
        drop(spool);
        let spool = Spool::open(&path, limits).unwrap();
        let record = spool.next().unwrap().unwrap();
        assert_eq!(record.record_id, id);
        assert_eq!(record.payload.as_slice(), vec![255; MAX_RECORD_BYTES]);
        spool.ack(&id).unwrap();
        assert_eq!(spool.usage().unwrap(), (0, 0));
    }

    #[test]
    fn capacity_check_and_atomic_enqueue_share_one_serialization_gate() {
        let temp = tempfile::tempdir().unwrap();
        let spool = Arc::new(
            Spool::open(
                temp.path().join("spool"),
                SpoolLimits {
                    max_entries: 4,
                    ..limits()
                },
            )
            .unwrap(),
        );
        let start = Arc::new(Barrier::new(16));
        let workers: Vec<_> = (0..16)
            .map(|time| {
                let spool = spool.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    spool.enqueue(
                        ContractId::new("test").unwrap(),
                        time,
                        BoundedBytes::new(vec![1], 1).unwrap(),
                    )
                })
            })
            .collect();
        let mut accepted = 0;
        for worker in workers {
            match worker.join().unwrap() {
                Ok(_) => accepted += 1,
                Err(Error::SpoolFull) => (),
                other => panic!("unexpected enqueue result: {other:?}"),
            }
        }
        assert_eq!(accepted, 4);
        assert_eq!(spool.usage().unwrap().0, 4);
        assert_eq!(
            spool
                .directory
                .files(InventoryLimits {
                    max_entries: 5,
                    max_total_bytes: limits().max_bytes
                })
                .unwrap()
                .len(),
            5
        );
    }

    #[test]
    fn identity_isolation_preserves_bytes_capacity_and_read_only_reason_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("spool");
        let bounded = SpoolLimits {
            max_entries: 1,
            ..limits()
        };
        let spool = Spool::open(&root, limits()).unwrap();
        let id = enqueue(&spool, 1, 100, b"original evidence".to_vec());
        let source = current_path(&spool);
        let bytes = fs::read(&source).unwrap();
        let destination = source.with_extension("identity");
        // A colliding target is never overwritten, and the pending source remains.
        fs::write(&destination, "preexisting evidence").unwrap();
        assert!(
            spool
                .quarantine(&id, QuarantineReason::IdentityMismatch)
                .is_err()
        );
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert_eq!(fs::read(&destination).unwrap(), b"preexisting evidence");
        fs::remove_file(&destination).unwrap();
        spool
            .quarantine(&id, QuarantineReason::IdentityMismatch)
            .unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert!(spool.next().unwrap().is_none());
        assert!(matches!(spool.ack(&id), Err(Error::RecordNotFound)));
        drop(spool);
        let health = Spool::inspect_existing(&root, bounded).unwrap();
        assert_eq!(health.identity_mismatch_entries, 1);
        assert_eq!(health.quarantined_entries, 1);
        assert!(!health.healthy && !health.capacity_remaining);
        let spool = Spool::open(&root, bounded).unwrap();
        assert!(matches!(
            spool.enqueue(
                ContractId::new("current").unwrap(),
                2,
                BoundedBytes::new(vec![1], 1).unwrap()
            ),
            Err(Error::SpoolFull)
        ));
        assert_eq!(spool.doctor().unwrap(), health);
        assert_eq!(fs::read(destination).unwrap(), bytes);
    }

    #[test]
    fn physical_container_bytes_and_quarantines_consume_capacity() {
        let temp = tempfile::tempdir().unwrap();
        let record = SpoolRecord {
            record_id: RecordId::parse("1".repeat(32)).unwrap(),
            contract_id: ContractId::new("example.current").unwrap(),
            created_at_micros: 1,
            payload: BoundedBytes::new(vec![0], 1).unwrap(),
        };
        let size = encode(&record, 100).unwrap().len() as u64;
        let spool = Spool::open(
            temp.path().join("spool"),
            SpoolLimits {
                max_bytes: size,
                ..limits()
            },
        )
        .unwrap();
        let id = enqueue(&spool, 1, 100, vec![0]);
        spool.quarantine(&id, QuarantineReason::Corrupt).unwrap();
        assert_eq!(spool.usage().unwrap(), (0, size));
        assert!(matches!(
            spool.enqueue(
                ContractId::new("test").unwrap(),
                2,
                BoundedBytes::new(vec![1], 1).unwrap()
            ),
            Err(Error::SpoolFull)
        ));
        let health = spool.doctor().unwrap();
        assert!(!health.healthy && !health.capacity_remaining);
        assert_eq!(health.quarantined_entries, 1);
    }

    #[test]
    fn priority_and_timestamp_order_is_stable_without_replaying_acked_records() {
        let temp = tempfile::tempdir().unwrap();
        let spool = Spool::open(temp.path().join("spool"), limits()).unwrap();
        let low = enqueue(&spool, 1, 200, vec![1]);
        let later = enqueue(&spool, 3, 10, vec![3]);
        let early = enqueue(&spool, 2, 10, vec![2]);
        for id in [early, later, low] {
            assert_eq!(spool.next().unwrap().unwrap().record_id, id);
            spool.ack(&id).unwrap();
            assert!(matches!(spool.ack(&id), Err(Error::RecordNotFound)));
        }
        assert!(spool.next().unwrap().is_none());
    }

    #[test]
    fn checksum_corruption_is_quarantined_without_losing_later_records() {
        let temp = tempfile::tempdir().unwrap();
        let spool = Spool::open(temp.path().join("spool"), limits()).unwrap();
        enqueue(&spool, 1, 100, vec![1, 2]);
        let corrupt = current_path(&spool);
        let mut bytes = fs::read(&corrupt).unwrap();
        bytes[MAGIC.len()] ^= 1;
        fs::write(&corrupt, bytes).unwrap();
        let good = enqueue(&spool, 2, 100, vec![3]);
        assert_eq!(spool.next().unwrap().unwrap().record_id, good);
        assert!(corrupt.with_extension("bad").exists());
        assert_eq!(spool.doctor().unwrap().quarantined_entries, 1);
    }

    #[test]
    fn container_identity_must_match_filename_even_with_valid_checksum() {
        let temp = tempfile::tempdir().unwrap();
        let spool = Spool::open(temp.path().join("spool"), limits()).unwrap();
        let id = enqueue(&spool, 1, 100, vec![1]);
        let original = current_path(&spool);
        let moved = spool
            .directory
            .path()
            .join(record_name(100, 2, &id, None).unwrap().as_path());
        fs::rename(original, &moved).unwrap();
        assert!(spool.next().unwrap().is_none());
        assert!(moved.with_extension("bad").exists());
    }

    #[test]
    fn oversized_container_is_quarantined_using_a_bounded_read() {
        let temp = tempfile::tempdir().unwrap();
        let spool = Spool::open(temp.path().join("spool"), limits()).unwrap();
        enqueue(&spool, 1, 100, vec![1]);
        let path = current_path(&spool);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len((limits().max_record_bytes + CONTAINER_OVERHEAD + 1) as u64)
            .unwrap();
        assert!(spool.next().unwrap().is_none());
        assert!(path.with_extension("bad").exists());
    }

    #[test]
    fn cleanup_requires_the_exclusive_process_lock_and_exact_temporary_shape() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        let spool = Spool::open(&path, limits()).unwrap();
        let temporary = path.join(format!(".sarmg-atomic-{}.tmp", "a".repeat(32)));
        fs::write(&temporary, b"interrupted").unwrap();
        assert!(matches!(
            Spool::open(&path, limits()),
            Err(Error::AlreadyRunning)
        ));
        assert!(temporary.exists());
        drop(spool);
        let reopened = Spool::open(&path, limits()).unwrap();
        assert!(!temporary.exists());
        drop(reopened);
        let unrecognized = path.join("unowned.tmp");
        fs::write(&unrecognized, b"evidence").unwrap();
        assert!(matches!(
            Spool::open(&path, limits()),
            Err(Error::InvalidRecord)
        ));
        assert_eq!(fs::read(unrecognized).unwrap(), b"evidence");
    }

    #[test]
    fn directory_path_rebinding_does_not_redirect_reads_writes_or_ack() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("spool");
        let spool = Spool::open(&original, limits()).unwrap();
        let id = enqueue(&spool, 1, 100, vec![1]);
        let moved = temp.path().join("moved");
        #[cfg(not(windows))]
        {
            fs::rename(&original, &moved).unwrap();
            fs::create_dir(&original).unwrap();
            fs::write(original.join("victim"), b"untouched").unwrap();
        }
        #[cfg(windows)]
        {
            // The native directory handle denies delete sharing: rebinding is
            // rejected while held, instead of following an openat-style inode.
            assert!(fs::rename(&original, &moved).is_err());
            assert!(!moved.exists());
        }
        assert_eq!(spool.next().unwrap().unwrap().record_id, id);
        enqueue(&spool, 2, 100, vec![2]);
        spool.ack(&id).unwrap();
        #[cfg(not(windows))]
        assert_eq!(fs::read_dir(&original).unwrap().count(), 1);
        assert_eq!(spool.usage().unwrap().0, 1);
        #[cfg(windows)]
        {
            drop(spool);
            fs::rename(&original, &moved).unwrap();
            assert_eq!(Spool::open(&moved, limits()).unwrap().usage().unwrap().0, 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn linked_or_special_entries_are_not_read_deleted_or_quarantined() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        let spool = Spool::open(&path, limits()).unwrap();
        let id = enqueue(&spool, 1, 100, vec![1]);
        let target = current_path(&spool);
        fs::remove_file(&target).unwrap();
        let victim = temp.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, &target).unwrap();
        assert!(spool.next().is_err());
        assert!(spool.ack(&id).is_err());
        fs::remove_file(&target).unwrap();
        fs::hard_link(&victim, &target).unwrap();
        assert!(spool.next().is_err());
        assert!(spool.ack(&id).is_err());
        assert_eq!(fs::read(victim).unwrap(), b"untouched");
    }

    #[test]
    fn current_limits_names_and_negative_timestamp_are_strict() {
        assert!(
            SpoolLimits {
                max_bytes: MAX_SPOOL_BYTES + 1,
                ..limits()
            }
            .validate()
            .is_err()
        );
        assert!(
            SpoolLimits {
                max_entries: MAX_SPOOL_ENTRIES + 1,
                ..limits()
            }
            .validate()
            .is_err()
        );
        assert!(
            SpoolLimits {
                max_record_bytes: MAX_RECORD_BYTES + 1,
                ..limits()
            }
            .validate()
            .is_err()
        );
        assert!(RecordId::parse("A".repeat(32)).is_err());
        let temp = tempfile::tempdir().unwrap();
        let spool = Spool::open(temp.path().join("spool"), limits()).unwrap();
        assert!(matches!(
            spool.enqueue(
                ContractId::new("test").unwrap(),
                -1,
                BoundedBytes::new(vec![], 0).unwrap()
            ),
            Err(Error::InvalidRecord)
        ));
        assert_eq!(spool.usage().unwrap(), (0, 0));
    }

    #[test]
    fn runtime_limits_match_the_checked_profile() {
        let profile = include_str!("../../../../profiles/desktop-agent.toml");
        let (_, policy) = profile.split_once("[policy.agent_limits]").unwrap();
        let declared = policy
            .lines()
            .take_while(|line| !line.trim_start().starts_with('['))
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let (key, value) = line.split_once('=').unwrap();
                (key.trim(), value.trim().parse::<u64>().unwrap())
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            declared,
            std::collections::BTreeMap::from([
                ("max_record_bytes", MAX_RECORD_BYTES as u64),
                ("max_spool_bytes", MAX_SPOOL_BYTES),
                ("max_spool_entries", MAX_SPOOL_ENTRIES as u64),
            ])
        );
    }

    #[test]
    fn process_lock_excludes_an_independent_test_process() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        let _spool = Spool::open(&path, limits()).unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "spool::tests::process_lock_child", "--ignored"])
            .env("SARMG_SPOOL_LOCK_TEST_PATH", path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
    }

    #[test]
    #[ignore = "invoked by process_lock_excludes_an_independent_test_process"]
    fn process_lock_child() {
        let path =
            std::env::var_os("SARMG_SPOOL_LOCK_TEST_PATH").expect("parent supplies lock path");
        assert!(matches!(
            Spool::open(Path::new(&path), limits()),
            Err(Error::AlreadyRunning)
        ));
    }
}
