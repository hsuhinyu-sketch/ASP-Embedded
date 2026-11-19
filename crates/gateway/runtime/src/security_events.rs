//! Bounded, redacted security-event feed for auditing.
//!
//! This is intentionally an observability projection, not a policy store or authorization
//! control plane. Events retain identities, normalized actions, resources, decisions, hashes and
//! stable rule IDs, but never JWTs, prompts, document content, ACL lists or capability tokens.

use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, Utc};
use security_audit::AuditSink;
use security_types::{DecisionEffect, SecurityEvent, Subject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(test)]
use tokio::sync::broadcast;

const DEFAULT_CAPACITY: usize = 10_000;

static STORE: OnceLock<SecurityEventStore> = OnceLock::new();

#[derive(Clone)]
pub struct SecurityEventStore {
	inner: Arc<Inner>,
}

struct Inner {
	#[cfg(test)]
	capacity: usize,
	next_sequence: AtomicU64,
	#[cfg(test)]
	events: Mutex<VecDeque<SecurityTimelineEvent>>,
	#[cfg(test)]
	live: broadcast::Sender<SecurityTimelineEvent>,
	journal: Mutex<Option<EventJournal>>,
	#[cfg(test)]
	retention_seconds: Option<u64>,
	persistence_enabled: bool,
	persistence_failures: AtomicU64,
	capacity_state: AtomicU8,
}
enum EventJournal {
	Legacy(security_audit::JsonlJournal),
	Managed(security_audit::RotatingAuditJournal<SecurityTimelineEvent>),
}
impl EventJournal {
	fn append(&mut self, event: &SecurityTimelineEvent) -> std::io::Result<()> {
		match self {
			Self::Legacy(j) => j.append(event),
			Self::Managed(j) => j.append(event),
		}
	}
}

/// Event classes used in audit records. Values describe control-flow stages, never request content.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecurityEventKind {
	ManagementChange,
	Authorization,
	RagIngestion,
	RagRetrieval,
	RagContextAssembly,
	PiiInspection,
}

/// A sanitized event suitable for audit persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityTimelineEvent {
	pub sequence: u64,
	pub kind: SecurityEventKind,
	pub request_id: String,
	pub timestamp: DateTime<Utc>,
	pub user_id: Option<String>,
	pub agent_id: Option<String>,
	pub tenant_id: Option<String>,
	pub delegation_id: Option<String>,
	pub action: String,
	pub resource_type: String,
	pub resource_id: String,
	pub decision: Option<DecisionEffect>,
	pub policy_id: Option<String>,
	pub policy_version: Option<String>,
	pub details: BTreeMap<String, Value>,
}

/// Content-free operational state of the audit writer.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityAuditStatus {
	pub persistence_enabled: bool,
	pub persistence_healthy: bool,
	pub persistence_failures: u64,
	pub capacity: Option<security_audit::AuditJournalStatus>,
}

impl SecurityEventStore {
	pub fn new(_capacity: usize) -> Self {
		#[cfg(test)]
		let capacity = _capacity.max(1);
		#[cfg(test)]
		let (live, _) = broadcast::channel(capacity.min(1_024));
		Self {
			inner: Arc::new(Inner {
				#[cfg(test)]
				capacity,
				next_sequence: AtomicU64::new(0),
				#[cfg(test)]
				events: Mutex::new(VecDeque::with_capacity(capacity)),
				#[cfg(test)]
				live,
				journal: Mutex::new(None),
				#[cfg(test)]
				retention_seconds: None,
				persistence_enabled: false,
				persistence_failures: AtomicU64::new(0),
				capacity_state: AtomicU8::new(0),
			}),
		}
	}

	pub fn open(capacity: usize, path: &std::path::Path) -> std::io::Result<Self> {
		let (journal, events) =
			security_audit::JsonlJournal::open::<SecurityTimelineEvent>(path, capacity)?;
		let mut previous = 0;
		for event in &events {
			if event.sequence <= previous {
				return Err(std::io::Error::other("non-monotonic audit sequence"));
			}
			previous = event.sequence;
		}
		let mut store = Self::new(capacity);
		let inner = Arc::get_mut(&mut store.inner).expect("new store is exclusively owned");
		inner.next_sequence.store(previous, Ordering::Relaxed);
		#[cfg(test)]
		{
			inner.events = Mutex::new(events);
		}
		inner.journal = Mutex::new(Some(EventJournal::Legacy(journal)));
		inner.persistence_enabled = true;
		Ok(store)
	}

	pub fn record(&self, event: SecurityTimelineEvent) {
		if let Err(error) = self.record_checked(event, false) {
			if self.inner.capacity_state.load(Ordering::Relaxed)
				< security_audit::AuditCapacityState::Exhausted as u8
			{
				// Managed commit failures were already counted by record_inner.
				self
					.inner
					.persistence_failures
					.fetch_add(1, Ordering::Relaxed);
				tracing::error!(%error,"security audit record unavailable");
			}
		}
	}
	pub fn open_managed(
		capacity: usize,
		config: security_audit::AuditJournalConfig,
	) -> std::io::Result<Self> {
		let (journal, _events) = security_audit::RotatingAuditJournal::open(config.clone(), capacity)?;
		let status = journal.status();
		let mut store = Self::new(capacity);
		let inner = Arc::get_mut(&mut store.inner).expect("new store");
		inner
			.next_sequence
			.store(journal.next_sequence() - 1, Ordering::Relaxed);
		#[cfg(test)]
		{
			inner.events = Mutex::new(_events);
			inner.retention_seconds = Some(config.retention_seconds);
		}
		inner.journal = Mutex::new(Some(EventJournal::Managed(journal)));
		inner.persistence_enabled = true;
		store.report_capacity(&status, None);
		Ok(store)
	}
	pub fn status(&self) -> Result<SecurityAuditStatus, String> {
		// Metadata is cheap, but the writer may hold this lock during durable I/O.
		security_integration_runtime::with_blocking_io(|| {
			let journal = self
				.inner
				.journal
				.lock()
				.map_err(|_| "audit journal lock poisoned")?;
			let capacity = match journal.as_ref() {
				Some(EventJournal::Managed(journal)) => Some(journal.status()),
				_ => None,
			};
			let persistence_healthy = match &capacity {
				Some(status) => matches!(
					status.state,
					security_audit::AuditCapacityState::Ready | security_audit::AuditCapacityState::High
				),
				None => self.inner.persistence_enabled && journal.is_some(),
			};
			Ok(SecurityAuditStatus {
				persistence_enabled: self.inner.persistence_enabled,
				persistence_healthy,
				persistence_failures: self.inner.persistence_failures.load(Ordering::Relaxed),
				capacity,
			})
		})
	}
	fn report_capacity(
		&self,
		status: &security_audit::AuditJournalStatus,
		failure: Option<&std::io::Error>,
	) {
		use security_audit::AuditCapacityState;
		let previous = self
			.inner
			.capacity_state
			.swap(status.state as u8, Ordering::Relaxed);
		if previous == status.state as u8 {
			return;
		}
		let reason = failure.map(ToString::to_string);
		match status.state {
			AuditCapacityState::Ready => tracing::info!(
				writable_bytes = status.writable_bytes,
				"security audit capacity recovered"
			),
			AuditCapacityState::High => tracing::warn!(
				used_bytes = status.used_bytes,
				maximum_bytes = status.maximum_bytes,
				writable_bytes = status.writable_bytes,
				"security audit capacity high; less than 20 percent writable"
			),
			AuditCapacityState::Exhausted => {
				tracing::error!(reason=?reason, next_reclaim_at_millis=?status.next_reclaim_at_millis,
				"security audit capacity insufficient for a record; unexpired evidence retained")
			},
			AuditCapacityState::Failed => {
				tracing::error!(reason=?reason, "security audit writer quarantined; restart required after storage repair")
			},
		}
	}
	fn record_checked(&self, event: SecurityTimelineEvent, required: bool) -> Result<(), String> {
		// Synchronous callbacks still acknowledge persistence before returning. Let
		// other async requests run while this thread waits on the journal lock/disk.
		security_integration_runtime::with_blocking_io(|| self.record_inner(event, required))
	}
	fn record_inner(&self, event: SecurityTimelineEvent, required: bool) -> Result<(), String> {
		security_audit::StateJournal::encoded_len(&event, 16000)
			.map_err(|_| "audit event exceeds byte budget")?;
		// Serialize assignment, append and publication so concurrent writers cannot reorder IDs.
		let mut journal = self
			.inner
			.journal
			.lock()
			.map_err(|_| "audit journal lock poisoned")?;
		if required && !matches!(journal.as_ref(), Some(EventJournal::Managed(_))) {
			return Err("managed durable audit required".into());
		}
		let mut event = event;
		// Failed managed commits must not consume an event ID: a later retention
		// recovery must keep payload IDs aligned with the durable journal sequence.
		event.sequence = match journal.as_ref() {
			Some(EventJournal::Managed(writer)) => writer.next_sequence(),
			_ => self.inner.next_sequence.load(Ordering::Relaxed) + 1,
		};
		if let Some(writer) = journal.as_mut() {
			let result = writer.append(&event);
			if let EventJournal::Managed(writer) = writer {
				self.report_capacity(&writer.status(), result.as_ref().err());
			}
			if let Err(error) = result {
				self
					.inner
					.persistence_failures
					.fetch_add(1, Ordering::Relaxed);
				// Managed writers distinguish capacity (no write attempted) from a
				// permanently quarantined I/O failure. Keep their bounded status.
				if matches!(journal.as_ref(), Some(EventJournal::Managed(_))) {
					return Err(format!("audit commit failed: {error}"));
				}
				tracing::error!(%error, "security audit persistence failed; journal disabled until restart");
				*journal = None;
			}
		} else if self.inner.persistence_enabled {
			self
				.inner
				.persistence_failures
				.fetch_add(1, Ordering::Relaxed);
		}
		self
			.inner
			.next_sequence
			.store(event.sequence, Ordering::Relaxed);
		// Unit tests consume the in-memory projection.
		#[cfg(test)]
		{
			let mut events = self
				.inner
				.events
				.lock()
				.expect("security event store lock poisoned");
			if events.len() == self.inner.capacity {
				events.pop_front();
			}
			events.push_back(event.clone());
		}
		#[cfg(test)]
		let _ = self.inner.live.send(event);
		Ok(())
	}

	pub fn record_authorization(&self, event: SecurityEvent) {
		self.record(Self::authorization_event(event));
	}
	pub fn record_authorization_required(&self, event: SecurityEvent) -> Result<(), String> {
		self.record_checked(Self::authorization_event(event), true)
	}
	#[cfg(feature = "security-pii")]
	pub(crate) fn record_content_required(&self, event: SecurityTimelineEvent) -> Result<(), String> {
		self.record_checked(event, true)
	}
	fn authorization_event(event: SecurityEvent) -> SecurityTimelineEvent {
		SecurityTimelineEvent {
			sequence: 0,
			kind: SecurityEventKind::Authorization,
			request_id: event.request_id,
			timestamp: event.timestamp,
			user_id: event.subject.user_id,
			agent_id: event.subject.agent_id,
			tenant_id: event.subject.tenant_id,
			delegation_id: event.subject.delegation_id,
			action: format!("{:?}:{}", event.action.action_type, event.action.name),
			resource_type: format!("{:?}", event.resource.resource_type),
			resource_id: event.resource.id,
			decision: Some(event.decision),
			policy_id: event.policy_id,
			policy_version: event.policy_version,
			details: BTreeMap::from([
				(
					"decisionExpiresAt".into(),
					json!(event.decision_expires_at.map(|value| value.to_rfc3339())),
				),
				(
					"approval".into(),
					json!(event.authorization_context.approval),
				),
			]),
		}
	}

	pub fn record_rag_stage(
		&self,
		kind: SecurityEventKind,
		request_id: String,
		timestamp: DateTime<Utc>,
		subject: Subject,
		action: &str,
		resource_type: &str,
		resource_id: String,
		decision: Option<DecisionEffect>,
		details: BTreeMap<String, Value>,
	) {
		self.record(SecurityTimelineEvent {
			sequence: 0,
			kind,
			request_id,
			timestamp,
			user_id: subject.user_id,
			agent_id: subject.agent_id,
			tenant_id: subject.tenant_id,
			delegation_id: subject.delegation_id,
			action: action.into(),
			resource_type: resource_type.into(),
			resource_id,
			decision,
			policy_id: None,
			policy_version: None,
			details,
		});
	}

	#[cfg(test)]
	pub fn events(&self, request_id: Option<&str>, limit: usize) -> Vec<SecurityTimelineEvent> {
		let limit = limit.clamp(1, self.inner.capacity);
		self
			.inner
			.events
			.lock()
			.expect("security event store lock poisoned")
			.iter()
			.rev()
			.filter(|event| {
				self.inner.retention_seconds.is_none_or(|ttl| {
					event.timestamp.timestamp_millis()
						>= Utc::now()
							.timestamp_millis()
							.saturating_sub(ttl as i64 * 1000)
				})
			})
			.filter(|event| request_id.is_none_or(|request_id| event.request_id == request_id))
			.take(limit)
			.cloned()
			.collect()
	}

	#[cfg(test)]
	pub fn subscribe(&self) -> broadcast::Receiver<SecurityTimelineEvent> {
		self.inner.live.subscribe()
	}
}

/// Initializes the process-wide event store. The first application initialization wins; this is
/// intentional because the compatibility runtime runs one administrative control plane per process.
pub fn initialize(capacity: usize) -> SecurityEventStore {
	STORE
		.get_or_init(|| SecurityEventStore::new(capacity))
		.clone()
}

pub fn initialize_persistent(
	capacity: usize,
	path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
	if let Some(path) = path {
		let store = SecurityEventStore::open(capacity, path)?;
		STORE
			.set(store)
			.map_err(|_| anyhow::anyhow!("security store already initialized"))?;
	} else {
		initialize(capacity);
	}
	Ok(())
}
pub fn initialize_managed(
	capacity: usize,
	config: security_audit::AuditJournalConfig,
) -> anyhow::Result<()> {
	STORE
		.set(SecurityEventStore::open_managed(capacity, config)?)
		.map_err(|_| anyhow::anyhow!("security store already initialized"))?;
	Ok(())
}

pub fn store() -> SecurityEventStore {
	initialize(DEFAULT_CAPACITY)
}

/// Fan-out sink used by security pipelines: tracing remains the operational record while the
/// bounded projection makes sanitized events available for audit.
#[derive(Clone, Copy, Default)]
pub struct UiSecurityAuditSink;

impl AuditSink for UiSecurityAuditSink {
	fn is_blocking(&self) -> bool {
		store().inner.persistence_enabled
	}
	fn record_required(&self, event: SecurityEvent) -> Result<(), String> {
		store().record_authorization_required(event)
	}
	fn record(&self, event: SecurityEvent) {
		security_integration_runtime::TracingAuditSink.record(event.clone());
		store().record_authorization(event);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;

	fn directory() -> PathBuf {
		let path = std::env::temp_dir().join(format!("aisp-audit-{}", uuid::Uuid::new_v4()));
		std::fs::create_dir(&path).unwrap();
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
		}
		path
	}

	fn config(directory: PathBuf) -> security_audit::AuditJournalConfig {
		security_audit::AuditJournalConfig {
			directory,
			max_segment_bytes: 1_048_576,
			max_segments: 2,
			retention_seconds: 3600,
		}
	}

	fn event(request_id: String) -> SecurityTimelineEvent {
		SecurityTimelineEvent {
			sequence: 0,
			kind: SecurityEventKind::Authorization,
			request_id,
			timestamp: Utc::now(),
			user_id: Some("alice".into()),
			agent_id: Some("agent-a".into()),
			tenant_id: Some("tenant-a".into()),
			delegation_id: None,
			action: "ToolInvoke:echo".into(),
			resource_type: "Tool".into(),
			resource_id: "local/echo".into(),
			decision: Some(DecisionEffect::Allow),
			policy_id: Some("audit:required:toolInvoke".into()),
			policy_version: None,
			details: BTreeMap::new(),
		}
	}

	fn persisted(directory: &std::path::Path) -> Vec<Value> {
		let segment = std::fs::read_dir(directory)
			.unwrap()
			.map(|entry| entry.unwrap().path())
			.find(|path| {
				path
					.file_name()
					.unwrap()
					.to_string_lossy()
					.starts_with("segment-")
			})
			.unwrap();
		std::fs::read_to_string(segment)
			.unwrap()
			.lines()
			.map(|line| serde_json::from_str(line).unwrap())
			.collect()
	}

	#[test]
	fn required_events_survive_concurrent_writes_and_reopen_beyond_projection_capacity() {
		let directory = directory();
		let config = config(directory.clone());
		let store = SecurityEventStore::open_managed(2, config.clone()).unwrap();
		std::thread::scope(|scope| {
			for worker in 0..4 {
				let store = &store;
				scope.spawn(move || {
					for item in 0..8 {
						store
							.record_checked(event(format!("{worker}-{item}")), true)
							.unwrap();
					}
				});
			}
		});
		let rows = persisted(&directory);
		assert_eq!(rows.len(), 32);
		let mut requests = std::collections::HashSet::new();
		for (index, row) in rows.iter().enumerate() {
			assert_eq!(row["sequence"], index + 1);
			assert_eq!(row["event"]["sequence"], index + 1);
			assert_eq!(row["event"]["tenantId"], "tenant-a");
			requests.insert(row["event"]["requestId"].as_str().unwrap());
		}
		assert_eq!(requests.len(), 32);
		drop(store);
		let store = SecurityEventStore::open_managed(2, config).unwrap();
		store
			.record_checked(event("after-recovery".into()), true)
			.unwrap();
		let rows = persisted(&directory);
		assert_eq!(rows.len(), 33);
		assert_eq!(rows[32]["event"]["sequence"], 33);
		drop(store);
		std::fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn required_failure_stays_closed_and_does_not_publish_a_success() {
		let directory = directory();
		let config = config(directory.clone());
		let store = SecurityEventStore::open_managed(2, config.clone()).unwrap();
		store
			.record_checked(event("committed".into()), true)
			.unwrap();
		let segment = std::fs::read_dir(&directory)
			.unwrap()
			.map(|entry| entry.unwrap().path())
			.find(|path| {
				path
					.file_name()
					.unwrap()
					.to_string_lossy()
					.starts_with("segment-")
			})
			.unwrap();
		std::fs::OpenOptions::new()
			.write(true)
			.open(segment)
			.unwrap()
			.set_len(0)
			.unwrap();
		assert!(store.record_checked(event("failed".into()), true).is_err());
		assert_eq!(store.status().unwrap().persistence_failures, 1);
		store.record(event("ordinary-failed".into()));
		assert_eq!(store.status().unwrap().persistence_failures, 2);
		assert!(
			store
				.record_checked(event("still-failed".into()), true)
				.is_err()
		);
		assert!(persisted(&directory).is_empty());
		assert_eq!(store.events(None, 10)[0].request_id, "committed");
		drop(store);
		assert!(SecurityEventStore::open_managed(2, config).is_err());
		std::fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn oversized_events_are_rejected_before_sequence_or_persistence_changes() {
		let directory = directory();
		let store = SecurityEventStore::open_managed(2, config(directory.clone())).unwrap();
		let mut oversized = event("oversized".into());
		oversized
			.details
			.insert("reason".into(), json!("x".repeat(16000)));
		assert!(store.record_checked(oversized, true).is_err());
		store.record_checked(event("valid".into()), true).unwrap();
		let rows = persisted(&directory);
		assert_eq!(rows.len(), 1);
		assert_eq!(rows[0]["event"]["sequence"], 1);
		drop(store);
		std::fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn legacy_recovery_still_rejects_non_monotonic_event_sequences() {
		let directory = directory();
		let path = directory.join("legacy.jsonl");
		let (mut journal, _) =
			security_audit::JsonlJournal::open::<SecurityTimelineEvent>(&path, 2).unwrap();
		for sequence in [2, 1] {
			let mut value = event(sequence.to_string());
			value.sequence = sequence;
			journal.append(&value).unwrap();
		}
		drop(journal);
		assert!(SecurityEventStore::open(2, &path).is_err());
		std::fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn capacity_denial_can_recover_after_retention_without_sequence_gaps() {
		let directory = directory();
		let mut config = config(directory.clone());
		config.retention_seconds = 2;
		let store = SecurityEventStore::open_managed(2, config.clone()).unwrap();
		let mut full = false;
		for index in 0..512 {
			let mut value = event(index.to_string());
			value
				.details
				.insert("reason".into(), json!("x".repeat(15000)));
			if store.record_checked(value, true).is_err() {
				full = true;
				break;
			}
		}
		assert!(full);
		let status = store.status().unwrap();
		assert!(!status.persistence_healthy);
		let capacity = status.capacity.unwrap();
		assert_eq!(
			capacity.state,
			security_audit::AuditCapacityState::Exhausted
		);
		let sequence = capacity.next_sequence;
		let wait = capacity
			.next_reclaim_at_millis
			.unwrap()
			.saturating_sub(Utc::now().timestamp_millis())
			.max(0) as u64;
		std::thread::sleep(std::time::Duration::from_millis(wait + 20));
		store
			.record_checked(event("recovered".into()), true)
			.unwrap();
		let status = store.status().unwrap();
		assert!(status.persistence_healthy);
		assert!(status.persistence_failures > 0);
		assert_eq!(status.capacity.unwrap().next_sequence, sequence + 1);
		assert_eq!(store.inner.next_sequence.load(Ordering::Relaxed), sequence);
		let mut paths = std::fs::read_dir(&directory)
			.unwrap()
			.map(|entry| entry.unwrap().path())
			.filter(|p| {
				p.file_name()
					.unwrap()
					.to_string_lossy()
					.starts_with("segment-")
			})
			.collect::<Vec<_>>();
		paths.sort();
		let mut sequences = Vec::new();
		for path in paths {
			for line in std::fs::read_to_string(path).unwrap().lines() {
				let row: Value = serde_json::from_str(line).unwrap();
				assert_eq!(row["sequence"], row["event"]["sequence"]);
				sequences.push(row["sequence"].as_u64().unwrap());
			}
		}
		assert!(sequences.windows(2).all(|pair| pair[1] == pair[0] + 1));
		assert_eq!(sequences.last(), Some(&sequence));
		drop(store);
		let store = SecurityEventStore::open_managed(2, config).unwrap();
		assert_eq!(
			store.status().unwrap().capacity.unwrap().next_sequence,
			sequence + 1
		);
		drop(store);
		std::fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn managed_audit_keeps_bounded_test_projection_and_subscription() {
		let directory = directory();
		let store = SecurityEventStore::open_managed(2, config(directory.clone())).unwrap();
		let mut subscription = store.subscribe();
		for index in 1..=3 {
			store
				.record_checked(event(index.to_string()), true)
				.unwrap();
			assert_eq!(subscription.try_recv().unwrap().sequence, index);
		}
		assert_eq!(
			store
				.events(None, 10)
				.iter()
				.map(|event| event.sequence)
				.collect::<Vec<_>>(),
			vec![3, 2]
		);
		assert_eq!(persisted(&directory).len(), 3);
		drop(subscription);
		drop(store);
		std::fs::remove_dir_all(directory).unwrap();
	}
}
