use super::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Journal = RotatingAuditJournal<Value>;
struct Directory(PathBuf);
impl Directory {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!(
			"audit-capacity-{}-{}",
			std::process::id(),
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_nanos()
		));
		std::fs::create_dir(&path).unwrap();
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
		}
		Self(path)
	}
	fn config(&self, retention_seconds: u64) -> AuditJournalConfig {
		let directory = self.0.join("source");
		std::fs::create_dir(&directory).unwrap();
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
		}
		AuditJournalConfig {
			directory,
			max_segment_bytes: 1_048_576,
			max_segments: 2,
			retention_seconds,
		}
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.0);
	}
}
fn contents(directory: &Path) -> BTreeMap<String, Vec<u8>> {
	std::fs::read_dir(directory)
		.unwrap()
		.map(|entry| {
			let path = entry.unwrap().path();
			(
				path.file_name().unwrap().to_string_lossy().into_owned(),
				std::fs::read(path).unwrap(),
			)
		})
		.collect()
}
fn fill(journal: &mut Journal) {
	let event = json!({"payload": "x".repeat(15000)});
	let mut saw_high = false;
	for _ in 0..512 {
		if let Err(error) = journal.append(&event) {
			assert!(error.get_ref().unwrap().is::<CapacityExceeded>(), "{error}");
			assert!(saw_high);
			assert_eq!(journal.status().state, AuditCapacityState::Exhausted);
			return;
		}
		saw_high |= journal.status().state == AuditCapacityState::High;
	}
	panic!("audit journal did not reach the configured capacity");
}
fn wait_for_closed_retention(journal: &Journal) {
	let deadline = journal.status().next_reclaim_at_millis.unwrap();
	let wait = deadline
		.saturating_sub(chrono::Utc::now().timestamp_millis())
		.max(0) as u64;
	std::thread::sleep(Duration::from_millis(wait + 20));
}
#[test]
fn capacity_preserves_evidence_and_sequence_then_recovers_only_after_retention() {
	let directory = Directory::new();
	let config = directory.config(2);
	let (mut journal, _) = Journal::open(config.clone(), 1).unwrap();
	assert_eq!(journal.status().state, AuditCapacityState::Ready);
	assert_eq!(journal.status().writable_bytes, 2_097_152);
	fill(&mut journal);
	let before = contents(&config.directory);
	let sequence = journal.next_sequence();
	assert!(
		journal
			.append(&json!({"payload": "y".repeat(15000)}))
			.is_err()
	);
	assert_eq!(contents(&config.directory), before);
	assert_eq!(journal.next_sequence(), sequence);
	journal.append(&json!({"smallDenial": true})).unwrap();
	assert_eq!(journal.status().state, AuditCapacityState::Exhausted);
	wait_for_closed_retention(&journal);
	journal.append(&json!({"recovered": true})).unwrap();
	assert_eq!(journal.next_sequence(), sequence + 2);
	assert_ne!(journal.status().state, AuditCapacityState::Failed);
	assert_eq!(journal.status().segments, 1);
	drop(journal);
	let (journal, _) = Journal::open(config, 1).unwrap();
	assert_eq!(journal.next_sequence(), sequence + 2);
}
#[test]
fn real_storage_failure_stays_quarantined_after_the_file_is_repaired() {
	let directory = Directory::new();
	let config = directory.config(3600);
	let (mut journal, _) = Journal::open(config, 1).unwrap();
	journal.append(&json!({"committed": true})).unwrap();
	let path = journal.segments[0].path.clone();
	let committed = std::fs::read(&path).unwrap();
	std::fs::OpenOptions::new()
		.write(true)
		.open(&path)
		.unwrap()
		.set_len(0)
		.unwrap();
	assert!(journal.append(&json!({"forbidden": true})).is_err());
	assert_eq!(journal.status().state, AuditCapacityState::Failed);
	std::fs::write(&path, &committed).unwrap();
	assert!(journal.append(&json!({"stillForbidden": true})).is_err());
	assert_eq!(std::fs::read(path).unwrap(), committed);
}
#[test]
fn export_excludes_live_writers_and_preserves_even_expired_source_bytes() {
	let directory = Directory::new();
	let config = directory.config(2);
	let output = directory.0.join("archive");
	let (mut journal, _) = Journal::open(config.clone(), 1).unwrap();
	let payload = json!({"payload": "x".repeat(15000)});
	while journal.segments.len() < 2 {
		journal.append(&payload).unwrap();
	}
	assert!(Journal::export(config.clone(), &output).is_err());
	assert!(!output.exists());
	wait_for_closed_retention(&journal);
	let sequence = journal.next_sequence();
	drop(journal);
	let source = contents(&config.directory);
	let report = Journal::export(config.clone(), &output).unwrap();
	assert_eq!(report.last_sequence, sequence - 1);
	assert_eq!(report.files.len(), 3);
	assert_eq!(contents(&config.directory), source);
	for (name, bytes) in &source {
		assert_eq!(&std::fs::read(output.join(name)).unwrap(), bytes);
	}
	let manifest: Value =
		serde_json::from_slice(&std::fs::read(output.join("manifest.json")).unwrap()).unwrap();
	assert_eq!(manifest["lastSequence"], sequence - 1);
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		assert_eq!(
			std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
			0o700
		);
		for entry in std::fs::read_dir(&output).unwrap() {
			assert_eq!(
				entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
				0o600
			);
		}
	}
	assert!(Journal::export(config.clone(), &output).is_err());
	assert_eq!(contents(&config.directory), source);
	let (journal, _) = Journal::open(config, 1).unwrap();
	assert_eq!(journal.next_sequence(), sequence);
	assert_eq!(journal.status().segments, 1);
}
#[test]
fn export_does_not_create_missing_source_or_publish_a_corrupt_archive() {
	let directory = Directory::new();
	let config = directory.config(3600);
	let output = directory.0.join("archive");
	assert!(Journal::export(config.clone(), &output).is_err());
	assert!(contents(&config.directory).is_empty());
	assert!(!output.exists());
	let (mut journal, _) = Journal::open(config.clone(), 1).unwrap();
	journal.append(&json!({"committed": true})).unwrap();
	let path = journal.segments[0].path.clone();
	drop(journal);
	std::fs::write(path, b"{truncated").unwrap();
	let corrupt = contents(&config.directory);
	assert!(Journal::export(config.clone(), &output).is_err());
	assert!(!output.exists());
	assert_eq!(contents(&config.directory), corrupt);
}
#[test]
fn export_rejects_an_archive_inside_the_source_directory() {
	let directory = Directory::new();
	let config = directory.config(3600);
	let (journal, _) = Journal::open(config.clone(), 1).unwrap();
	drop(journal);
	let before = contents(&config.directory);
	assert!(Journal::export(config.clone(), &config.directory.join("archive")).is_err());
	assert_eq!(contents(&config.directory), before);
}
