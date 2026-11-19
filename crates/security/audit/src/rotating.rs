//! Private, bounded audit segments. Retention deletes only expired CLOSED prefixes.
//! Exhaustion preserves unexpired evidence and denies admission rather than overwriting it.
use crate::{StateJournal, StateJournalConfig};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
	collections::VecDeque,
	fs::File,
	io,
	path::{Path, PathBuf},
};

const CONTROL_MAX_BYTES: u64 = 67_108_864;

#[derive(Debug)]
struct CapacityExceeded;
impl std::fmt::Display for CapacityExceeded {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("audit capacity exhausted; unexpired evidence retained")
	}
}
impl std::error::Error for CapacityExceeded {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuditCapacityState {
	Ready,
	High,
	Exhausted,
	Failed,
}

/// Last validated writer state. This is operational metadata, never an execution grant.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditJournalStatus {
	pub state: AuditCapacityState,
	pub used_bytes: u64,
	pub maximum_bytes: u64,
	/// Current segment plus unused segment slots; closed-segment slack is not writable.
	pub writable_bytes: u64,
	pub segments: usize,
	pub maximum_segments: usize,
	pub control_bytes: u64,
	pub retention_seconds: u64,
	pub next_sequence: u64,
	pub last_commit_millis: i64,
	pub next_reclaim_at_millis: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditJournalConfig {
	pub directory: PathBuf,
	#[serde(default = "segment_bytes")]
	pub max_segment_bytes: u64,
	#[serde(default = "segments")]
	pub max_segments: usize,
	#[serde(default = "retention")]
	pub retention_seconds: u64,
}
fn segment_bytes() -> u64 {
	16 * 1024 * 1024
}
fn segments() -> usize {
	8
}
fn retention() -> u64 {
	604800
}
impl AuditJournalConfig {
	pub fn validate(&self) -> Result<(), String> {
		if !self.directory.is_absolute()
			|| !(1_048_576..=67_108_864).contains(&self.max_segment_bytes)
			|| !(2..=32).contains(&self.max_segments)
			|| self
				.max_segment_bytes
				.saturating_mul(self.max_segments as u64)
				> 536_870_912
			|| !(1..=31_536_000).contains(&self.retention_seconds)
		{
			return Err("invalid audit directory/segment/retention limits".into());
		}
		Ok(())
	}
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Control {
	Configuration {
		version: u32,
		config: AuditJournalConfig,
	},
	Head {
		start: u64,
	},
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry<T> {
	version: u32,
	sequence: u64,
	millis: i64,
	event: T,
}
struct Segment {
	start: u64,
	last_millis: i64,
	journal: StateJournal,
	path: PathBuf,
}
pub struct RotatingAuditJournal<T> {
	config: AuditJournalConfig,
	control: StateJournal,
	segments: VecDeque<Segment>,
	next_sequence: u64,
	highwater: i64,
	healthy: bool,
	capacity_blocked: bool,
	marker: std::marker::PhantomData<T>,
}
impl<T: Serialize + DeserializeOwned> RotatingAuditJournal<T> {
	pub fn open(config: AuditJournalConfig, capacity: usize) -> io::Result<(Self, VecDeque<T>)> {
		Self::open_inner(config, capacity, true)
	}
	fn open_inner(
		mut config: AuditJournalConfig,
		capacity: usize,
		create: bool,
	) -> io::Result<(Self, VecDeque<T>)> {
		config.validate().map_err(io::Error::other)?;
		// Persist and use the resolved private directory for both IO and retention deletion.
		// Later changes to a caller's symlink alias must never retarget cleanup.
		config.directory = config.directory.canonicalize()?;
		if capacity == 0 || capacity > 10000 {
			return Err(io::Error::other("audit projection capacity out of range"));
		}
		let spec = StateJournalConfig {
			path: config.directory.join("writer.jsonl"),
			max_bytes: CONTROL_MAX_BYTES,
		};
		let mut configured = false;
		let mut head = 0;
		let replay_control = |record| {
			match record {
				Control::Configuration {
					version: 1,
					config: found,
				} if !configured && found == config => configured = true,
				Control::Head { start } if configured && start > head => head = start,
				_ => return Err(io::Error::other("invalid audit control journal")),
			}
			Ok(())
		};
		let mut control = if create {
			StateJournal::open::<Control>(&spec, replay_control)?
		} else {
			StateJournal::open_existing::<Control>(&spec, replay_control)?
		};
		if control.is_fresh() {
			control.append(&Control::Configuration {
				version: 1,
				config: config.clone(),
			})?;
		}
		let mut paths = Vec::new();
		for item in std::fs::read_dir(&config.directory)? {
			let item = item?;
			let name = item.file_name();
			let name = name
				.to_str()
				.ok_or_else(|| io::Error::other("invalid audit filename"))?;
			if name == "writer.jsonl" {
				continue;
			}
			let number = name
				.strip_prefix("segment-")
				.and_then(|v| v.strip_suffix(".jsonl"))
				.filter(|v| v.len() == 20)
				.and_then(|v| v.parse::<u64>().ok())
				.filter(|v| *v > 0)
				.ok_or_else(|| io::Error::other("unknown file in dedicated audit directory"))?;
			paths.push((number, item.path()));
			if paths.len() > config.max_segments {
				return Err(io::Error::other("audit segment capacity exceeded"));
			}
		}
		paths.sort_by_key(|v| v.0);
		if paths.last().map_or(0, |v| v.0) != head {
			return Err(io::Error::other(
				"audit head missing or interrupted rotation",
			));
		}
		let now = chrono::Utc::now().timestamp_millis();
		let cutoff = now.saturating_sub(config.retention_seconds as i64 * 1000);
		let mut output = VecDeque::new();
		let mut journals = VecDeque::new();
		let mut previous = None;
		let mut highwater = 0;
		for (start, path) in paths {
			let mut first = true;
			let mut last_millis = 0;
			let spec = StateJournalConfig {
				path: path.clone(),
				max_bytes: config.max_segment_bytes,
			};
			let replay_entry = |entry: Entry<T>| {
				if entry.version != 1
					|| entry.millis < highwater
					|| entry.millis > now
					|| first && entry.sequence != start
					|| previous.is_some_and(|p: u64| p.checked_add(1) != Some(entry.sequence))
					|| StateJournal::encoded_len(&entry, 16383).is_err()
				{
					return Err(io::Error::other("invalid audit sequence/clock/record"));
				}
				first = false;
				previous = Some(entry.sequence);
				highwater = entry.millis;
				last_millis = entry.millis;
				if entry.millis >= cutoff {
					if output.len() == capacity {
						output.pop_front();
					}
					output.push_back(entry.event);
				}
				Ok(())
			};
			let journal = if create {
				StateJournal::open::<Entry<T>>(&spec, replay_entry)?
			} else {
				StateJournal::open_existing::<Entry<T>>(&spec, replay_entry)?
			};
			if first {
				return Err(io::Error::other("empty audit segment"));
			}
			journals.push_back(Segment {
				start,
				last_millis,
				journal,
				path,
			});
		}
		let next_sequence = previous
			.unwrap_or(0)
			.checked_add(1)
			.ok_or_else(|| io::Error::other("audit sequence exhausted"))?;
		let mut journal = Self {
			config,
			control,
			segments: journals,
			next_sequence,
			highwater,
			healthy: true,
			capacity_blocked: false,
			marker: Default::default(),
		};
		if create {
			journal.prune(now)?;
		}
		Ok((journal, output))
	}
	fn check(&mut self) -> io::Result<i64> {
		let now = chrono::Utc::now().timestamp_millis();
		let valid =
			self.control.check().is_ok() && self.segments.iter_mut().all(|s| s.journal.check().is_ok());
		if !self.healthy || !valid || now < self.highwater {
			self.healthy = false;
			return Err(io::Error::other("audit journal unavailable"));
		}
		Ok(now)
	}
	fn prune(&mut self, now: i64) -> io::Result<()> {
		let cutoff = now.saturating_sub(self.config.retention_seconds as i64 * 1000);
		while self.segments.len() > 1
			&& self
				.segments
				.front()
				.is_some_and(|s| s.last_millis < cutoff)
		{
			let old = self.segments.pop_front().expect("checked");
			self.capacity_blocked = false;
			let path = old.path.clone();
			drop(old);
			if std::fs::remove_file(&path)
				.and_then(|_| File::open(&self.config.directory)?.sync_all())
				.is_err()
			{
				self.healthy = false;
				return Err(io::Error::other("audit retention cleanup failed"));
			}
		}
		Ok(())
	}
	pub fn append(&mut self, event: &T) -> io::Result<()> {
		let result = self.append_inner(event);
		match &result {
			Err(error) if error.get_ref().is_some_and(|e| e.is::<CapacityExceeded>()) => {
				// No write was attempted. Future requests may reclaim expired closed segments.
				self.capacity_blocked = true;
			},
			Err(_) => self.healthy = false,
			// A smaller record may fit, but does not resolve the capacity warning.
			// Only reclamation clears this episode; every actual append is still checked.
			Ok(()) => {},
		}
		result
	}
	fn append_inner(&mut self, event: &T) -> io::Result<()> {
		let millis = self.check()?;
		self.prune(millis)?;
		let sequence = self.next_sequence;
		let entry = Entry {
			version: 1,
			sequence,
			millis,
			event,
		};
		let bytes = StateJournal::encoded_len(&entry, 16383)? as u64;
		if self
			.segments
			.back()
			.is_none_or(|s| s.journal.remaining_bytes() < bytes)
		{
			if self.segments.len() >= self.config.max_segments {
				return Err(io::Error::other(CapacityExceeded));
			}
			let path = self
				.config
				.directory
				.join(format!("segment-{sequence:020}.jsonl"));
			if std::fs::symlink_metadata(&path).is_ok() {
				return Err(io::Error::other("audit segment already exists"));
			}
			let mut journal = StateJournal::open::<Entry<T>>(
				&StateJournalConfig {
					path: path.clone(),
					max_bytes: self.config.max_segment_bytes,
				},
				|_| Err(io::Error::other("unexpected audit record")),
			)?;
			journal.append(&entry)?;
			self.control.append(&Control::Head { start: sequence })?;
			self.segments.push_back(Segment {
				start: sequence,
				last_millis: millis,
				journal,
				path,
			});
		} else {
			let last = self.segments.back_mut().expect("exists");
			last.journal.append(&entry)?;
			last.last_millis = millis;
		}
		self.next_sequence = sequence
			.checked_add(1)
			.ok_or_else(|| io::Error::other("audit sequence exhausted"))?;
		self.highwater = millis;
		self.prune(millis)
	}
	pub fn history(&mut self, before: Option<u64>, limit: usize) -> io::Result<VecDeque<T>> {
		if !(1..=1000).contains(&limit) {
			return Err(io::Error::other("history limit out of range"));
		}
		let now = self.check()?;
		self.prune(now)?;
		let cutoff = now.saturating_sub(self.config.retention_seconds as i64 * 1000);
		let mut result = VecDeque::new();
		for segment in self.segments.iter_mut().rev() {
			if before.is_some_and(|id| segment.start >= id) {
				continue;
			}
			let remaining = limit - result.len();
			let mut page = VecDeque::new();
			let mut expected = segment.start;
			segment.journal.visit::<Entry<T>>(|entry| {
				if entry.sequence != expected || entry.version != 1 || entry.millis > now {
					return Err(io::Error::other("audit history sequence/clock mismatch"));
				}
				expected = expected
					.checked_add(1)
					.ok_or_else(|| io::Error::other("audit sequence exhausted"))?;
				if entry.millis >= cutoff && before.is_none_or(|id| entry.sequence < id) {
					if page.len() == remaining {
						page.pop_front();
					}
					page.push_back(entry.event);
				}
				Ok(())
			})?;
			for event in page.into_iter().rev() {
				result.push_front(event);
			}
			if result.len() == limit {
				break;
			}
		}
		Ok(result)
	}
	pub fn next_sequence(&self) -> u64 {
		self.next_sequence
	}
	/// Bounded metadata only: no directory scan, replay, pruning or storage mutation.
	pub fn status(&self) -> AuditJournalStatus {
		let maximum_bytes = self.config.max_segment_bytes * self.config.max_segments as u64;
		let writable_bytes = self
			.segments
			.back()
			.map_or(0, |s| s.journal.remaining_bytes())
			+ (self.config.max_segments - self.segments.len()) as u64 * self.config.max_segment_bytes;
		let state = if !self.healthy {
			AuditCapacityState::Failed
		} else if self.capacity_blocked {
			AuditCapacityState::Exhausted
		} else if writable_bytes <= maximum_bytes / 5 {
			AuditCapacityState::High
		} else {
			AuditCapacityState::Ready
		};
		AuditJournalStatus {
			state,
			used_bytes: self
				.segments
				.iter()
				.map(|s| self.config.max_segment_bytes - s.journal.remaining_bytes())
				.sum(),
			maximum_bytes,
			writable_bytes,
			segments: self.segments.len(),
			maximum_segments: self.config.max_segments,
			control_bytes: CONTROL_MAX_BYTES - self.control.remaining_bytes(),
			retention_seconds: self.config.retention_seconds,
			next_sequence: self.next_sequence,
			last_commit_millis: self.highwater,
			next_reclaim_at_millis: (self.segments.len() > 1).then(|| {
				self
					.segments
					.front()
					.expect("nonempty")
					.last_millis
					.saturating_add(self.config.retention_seconds as i64 * 1000)
					.saturating_add(1)
			}),
		}
	}

	/// Offline byte-for-byte export. The normal exclusive writer locks exclude a live Gateway.
	/// Export never prunes or acknowledges removal; the manifest is written only after all copies.
	pub fn export(config: AuditJournalConfig, destination: &Path) -> io::Result<AuditExportReport> {
		let (mut journal, _) = Self::open_inner(config, 1, false)?;
		if !destination.is_absolute() || destination.file_name().is_none() {
			return Err(io::Error::other(
				"audit export requires a new absolute output directory",
			));
		}
		let destination = destination
			.parent()
			.expect("absolute path")
			.canonicalize()?
			.join(destination.file_name().expect("checked"));
		if destination.starts_with(&journal.config.directory) {
			return Err(io::Error::other(
				"audit export must be outside the source directory",
			));
		}
		let mut builder = std::fs::DirBuilder::new();
		#[cfg(unix)]
		{
			use std::os::unix::fs::DirBuilderExt;
			builder.mode(0o700);
		}
		builder.create(&destination)?;
		let mut files = Vec::new();
		files.push(AuditExportFile {
			name: "writer.jsonl".into(),
			bytes: journal.control.copy_to(&destination.join("writer.jsonl"))?,
		});
		for segment in &mut journal.segments {
			let name = format!("segment-{:020}.jsonl", segment.start);
			let bytes = segment.journal.copy_to(&destination.join(&name))?;
			files.push(AuditExportFile { name, bytes });
		}
		journal.check()?;
		let report = AuditExportReport {
			version: 1,
			source: journal.config.directory.clone(),
			last_sequence: journal.next_sequence - 1,
			files,
		};
		let mut options = std::fs::OpenOptions::new();
		options.create_new(true).write(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		let mut manifest = options.open(destination.join("manifest.json"))?;
		serde_json::to_writer_pretty(&mut manifest, &report).map_err(io::Error::other)?;
		manifest.sync_all()?;
		File::open(&destination)?.sync_all()?;
		File::open(destination.parent().expect("resolved parent"))?.sync_all()?;
		Ok(report)
	}
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditExportReport {
	pub version: u32,
	pub source: PathBuf,
	pub last_sequence: u64,
	pub files: Vec<AuditExportFile>,
}

#[derive(Debug, Serialize)]
pub struct AuditExportFile {
	pub name: String,
	pub bytes: u64,
}

#[cfg(test)]
#[path = "rotating_tests.rs"]
mod tests;
