use super::*;
use crate::task_cleanup::{CleanupAdmission, TaskCleanupConfig};

fn config() -> ExecutionBudgetConfig {
	serde_json::from_value(serde_json::json!({
		"namespace":"budget-index", "maxContexts":16384, "maxContextsPerOwner":16384,
		"maxModelCalls":1,"maxToolCalls":1,"maxAttempts":2,"maxConcurrent":2
	}))
	.unwrap()
}
fn owner() -> VerifiedOwner {
	VerifiedOwner::from_identity(
		&security_pipeline::GatewayIdentity {
			tenant_id: Some("tenant".into()),
			user_id: Some("alice".into()),
			..Default::default()
		},
		"issuer",
	)
	.unwrap()
}
fn record(index: usize, base: Instant) -> Arc<Record> {
	let mut config = config();
	config.namespace = format!("namespace-{}", index % 3);
	if index.is_multiple_of(4) {
		config.task_cleanup = Some(TaskCleanupConfig {
			grace_seconds: 3,
			..Default::default()
		});
	}
	let mut owner = owner();
	owner.user = Some(format!("owner-{}", index % 5));
	Arc::new(Record {
		cleanup: config.task_cleanup.as_ref().map(|c| {
			Arc::new(crate::task_cleanup::LocalCleanupLedger::new(
				c.clone(),
				Default::default(),
			))
		}),
		cancellation: CancellationToken::new(),
		invocations: Default::default(),
		invocation_slots: Default::default(),
		id: index.to_string(),
		owner,
		fingerprint: "config".into(),
		config,
		deadline: base + Duration::from_secs((index % 7) as u64),
		usage: Default::default(),
	})
}
fn assert_counts(table: &BudgetRecords) {
	let mut expected: HashMap<String, HashMap<VerifiedOwner, usize>> = HashMap::new();
	for record in table.records.values() {
		*expected
			.entry(record.config.namespace.clone())
			.or_default()
			.entry(record.owner.clone())
			.or_default() += 1;
	}
	assert_eq!(table.counts.len(), expected.len());
	for (namespace, owners) in expected {
		let counts = &table.counts[&namespace];
		assert_eq!(counts.total, owners.values().sum::<usize>());
		assert_eq!(counts.owners, owners);
	}
	match table
		.records
		.values()
		.map(|r| r.cleanup_deadline().unwrap_or(r.deadline))
		.min()
	{
		Some(earliest) => assert!(table.next_reap.is_some_and(|hint| hint <= earliest)),
		None => assert!(table.next_reap.is_none()),
	}
}

#[test]
fn indexed_reaping_matches_full_scan_with_cancellation_leases_and_cleanup() {
	let base = Instant::now();
	let mut table = BudgetRecords::default();
	let mut reference = HashMap::new();
	let mut cleanups = Vec::new();
	for index in 0..256 {
		let record = record(index, base);
		if index.is_multiple_of(3) {
			record.cancel().unwrap();
		}
		if index.is_multiple_of(5) {
			record.usage.lock().unwrap().concurrent = 1;
		}
		if let Some(cleanup) = &record.cleanup {
			if let CleanupAdmission::New(lease) = cleanup.begin("task", None).unwrap() {
				cleanups.push(lease);
			}
		}
		reference.insert(record.id.clone(), record.clone());
		table.insert(record);
	}
	for seconds in [0, 1, 2, 4, 8, 12] {
		let now = base + Duration::from_secs(seconds);
		reference.retain(|_, r| {
			r.deadline > now
				|| r.cleanup_deadline().is_ok_and(|until| until > now)
				|| r.usage.lock().map_or(true, |u| u.concurrent != 0)
				|| r.cleanup.as_ref().is_some_and(|c| c.active())
		});
		table.reap(now);
		assert_eq!(table.records.len(), reference.len());
		assert!(reference.keys().all(|id| table.records.contains_key(id)));
		assert_counts(&table);
	}
	assert!(!table.records.is_empty());
	for record in reference.values() {
		record.usage.lock().unwrap().concurrent = 0;
	}
	drop(cleanups);
	table.reap(base + Duration::from_secs(12));
	assert!(table.records.is_empty());
	assert_counts(&table);
	// A newly admitted earlier deadline must move the hint back after a later one.
	table.insert(record(6, base));
	table.insert(record(1, base));
	table.reap(base + Duration::from_secs(1));
	assert_eq!(table.records.len(), 1);
	assert_counts(&table);
}

#[test]
fn capacity_counts_use_the_complete_owner_and_current_limits() {
	let store = InMemoryExecutionBudgetStore::default();
	let mut config = config();
	config.max_contexts_per_owner = 1;
	let first = owner();
	let mut owners = vec![first.clone()];
	for field in 0..6 {
		let mut other = first.clone();
		match field {
			0 => other.issuer.push_str("-other"),
			1 => other.tenant.push_str("-other"),
			2 => other.user = Some("bob".into()),
			3 => other.agent = Some("agent".into()),
			4 => other.client = Some("client".into()),
			_ => other.delegation = Some("delegation".into()),
		}
		owners.push(other);
	}
	for owner in owners {
		store.create(&config, owner, "config".into()).unwrap();
	}
	assert!(matches!(
		store.create(&config, first.clone(), "new-config".into()),
		Err(BudgetError::Capacity)
	));
	config.max_contexts_per_owner = 2;
	store
		.create(&config, first.clone(), "new-config".into())
		.unwrap()
		.cancel()
		.unwrap();
	assert!(matches!(
		store.create(&config, first, "config".into()),
		Err(BudgetError::Capacity)
	));
	config.max_contexts = 8;
	assert!(matches!(
		store.create(&config, owner(), "config".into()),
		Err(BudgetError::Capacity)
	));
	assert_counts(&store.0.lock().unwrap());
}

#[test]
fn global_capacity_and_expired_poisoned_usage_remain_fail_closed() {
	let store = InMemoryExecutionBudgetStore::default();
	let base = Instant::now();
	{
		let mut table = store.0.lock().unwrap();
		for index in 0..16384 {
			table.insert(record(index, base + Duration::from_secs(300)));
		}
	}
	assert!(matches!(
		store.create(&config(), owner(), "config".into()),
		Err(BudgetError::Capacity)
	));
	let poisoned = record(0, base);
	let usage = poisoned.usage.clone();
	let _ = std::panic::catch_unwind(move || {
		let _usage = usage.lock().unwrap();
		panic!("poisoned usage fixture");
	});
	let mut table = BudgetRecords::default();
	table.insert(poisoned);
	table.reap(base + Duration::from_secs(10));
	assert_eq!(table.records.len(), 1);
	assert_counts(&table);
}

struct Directory(std::path::PathBuf);
impl Directory {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!("budget-index-{}", uuid::Uuid::new_v4()));
		std::fs::create_dir(&path).unwrap();
		Self(path)
	}
	fn spec(&self) -> durable::ExecutionStorageConfig {
		durable::ExecutionStorageConfig::Journal {
			path: self.0.join("budget.jsonl"),
			max_bytes: 1_048_576,
		}
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.0);
	}
}

#[test]
fn recovered_cancelled_and_exhausted_budgets_still_consume_capacity() {
	let dir = Directory::new();
	let mut config = config();
	config.max_contexts = 2;
	config.max_contexts_per_owner = 2;
	config.storage = Some(dir.spec());
	let id = {
		let store = durable::DurableExecutionBudgetStore::open(dir.spec(), &config.namespace).unwrap();
		let first = store.create(&config, owner(), "config".into()).unwrap();
		let lease = first
			.reserve(CallKind::Model, &LogicalCharge::default())
			.unwrap();
		drop(lease);
		let id = first.id().to_owned();
		store
			.create(&config, owner(), "config".into())
			.unwrap()
			.cancel()
			.unwrap();
		id
	};
	let store = durable::DurableExecutionBudgetStore::open(dir.spec(), &config.namespace).unwrap();
	assert!(matches!(
		store.create(&config, owner(), "config".into()),
		Err(BudgetError::Capacity)
	));
	let first = store.resolve(&id, &config, &owner(), "config").unwrap();
	assert!(matches!(
		first.reserve(CallKind::Model, &LogicalCharge::default()),
		Err(BudgetError::ModelCalls)
	));
	let mut foreign = owner();
	foreign.tenant = "foreign".into();
	assert!(matches!(
		store.resolve(&id, &config, &foreign, "config"),
		Err(BudgetError::InvalidContext)
	));
	assert!(matches!(
		store.resolve(&id, &config, &owner(), "changed"),
		Err(BudgetError::InvalidContext)
	));
}

#[test]
fn failed_persistence_never_returns_a_new_handle_or_reuses_capacity() {
	let dir = Directory::new();
	let mut config = config();
	config.storage = Some(dir.spec());
	let store = durable::DurableExecutionBudgetStore::open(dir.spec(), &config.namespace).unwrap();
	let first = store.create(&config, owner(), "config".into()).unwrap();
	let path = dir.0.join("budget.jsonl");
	// Keep the inode/path valid, but exhaust the configured journal capacity.
	std::fs::OpenOptions::new()
		.write(true)
		.open(&path)
		.unwrap()
		.set_len(1_048_576)
		.unwrap();
	assert!(matches!(
		store.create(&config, owner(), "config".into()),
		Err(BudgetError::Unavailable)
	));
	assert!(matches!(
		store.resolve(first.id(), &config, &owner(), "config"),
		Err(BudgetError::Unavailable)
	));
	assert!(matches!(
		store.create(&config, owner(), "config".into()),
		Err(BudgetError::Unavailable)
	));
}

#[test]
fn expired_in_flight_records_release_capacity_only_after_the_lease_ends() {
	let dir = Directory::new();
	let mut config = config();
	config.max_duration_seconds = 1;
	config.max_contexts = 1;
	config.max_contexts_per_owner = 1;
	let memory: Arc<dyn ExecutionBudgetStore> = Arc::new(InMemoryExecutionBudgetStore::default());
	let mut durable_config = config.clone();
	durable_config.storage = Some(dir.spec());
	let durable: Arc<dyn ExecutionBudgetStore> =
		durable::DurableExecutionBudgetStore::open(dir.spec(), &config.namespace).unwrap();
	let cases = [(memory, config), (durable, durable_config)];
	let mut active = Vec::new();
	for (store, config) in &cases {
		let handle = store.create(config, owner(), "config".into()).unwrap();
		let lease = handle
			.reserve(CallKind::Transport, &LogicalCharge::default())
			.unwrap();
		handle.cancel().unwrap();
		active.push((handle, lease));
	}
	let deadline = active.iter().map(|(h, _)| h.deadline()).max().unwrap();
	std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5));
	for ((store, config), (old, lease)) in cases.iter().zip(active) {
		assert!(matches!(
			store.create(config, owner(), "config".into()),
			Err(BudgetError::Capacity)
		));
		drop(lease);
		let next = store.create(config, owner(), "config".into()).unwrap();
		assert_ne!(next.id(), old.id());
		assert!(matches!(
			store.resolve_for_control(old.id(), config, &owner(), "config"),
			Err(BudgetError::InvalidContext)
		));
		assert!(matches!(
			store.create(config, owner(), "config".into()),
			Err(BudgetError::Capacity)
		));
	}
}
