use super::*;
use security_audit::InMemoryAuditSink;
use security_types::CheckStage;

fn allowed() -> SecurityConfig {
	serde_json::from_value(serde_json::json!({"mode":"enforce", "policies":[
		{"id":"allow-model", "enabled":true,"effect":"allow","actionType":"modelInvoke"}
	]}))
	.unwrap()
}

#[test]
fn candidate_does_not_contact_or_construct_remote_pdp_but_dispatch_fails_closed() {
	let mut config = allowed();
	config.remote_pdp = Some(
		serde_json::from_value(serde_json::json!({"endpoint":"http://invalid.example/pdp"})).unwrap(),
	);
	let action =
		security_pipeline::model_invoke_for_identity("internal", Default::default(), "local-model");
	let sink = InMemoryAuditSink::default();
	assert!(evaluate_at_stage(&config, CheckStage::Candidate, &action, None, &sink).is_ok());
	assert!(evaluate_at_stage(&config, CheckStage::Dispatch, &action, None, &sink).is_err());
	let events = sink.events();
	assert_eq!(events[0].decision, DecisionEffect::Allow);
	assert!(
		events[0]
			.policy_id
			.as_ref()
			.unwrap()
			.starts_with("prefilter:")
	);
	assert_eq!(events.last().unwrap().decision, DecisionEffect::Deny);
}

#[test]
fn candidate_pass_does_not_replace_durable_audit_admission() {
	let mut config = allowed();
	config.required_audit = Some(required_audit::RequiredAuditConfig {
		action_types: vec![security_types::ActionType::ModelInvoke],
	});
	let action =
		security_pipeline::model_invoke_for_identity("internal", Default::default(), "local-model");
	let sink = InMemoryAuditSink::default();
	assert!(evaluate_at_stage(&config, CheckStage::Candidate, &action, None, &sink).is_ok());
	assert!(evaluate_at_stage(&config, CheckStage::Dispatch, &action, None, &sink).is_err());
	config.required_audit = None;
	assert!(evaluate_at_stage(&config, CheckStage::Dispatch, &action, None, &sink).is_ok());
}

#[tokio::test]
async fn awaited_evaluation_preserves_modes_and_required_audit_failure() {
	let action = security_pipeline::model_invoke_for_identity("awaited", Default::default(), "local");
	for remote in [false, true] {
		for mode in [
			SecurityMode::Enforce,
			SecurityMode::Audit,
			SecurityMode::Shadow,
		] {
			let mut config = SecurityConfig::default();
			config.mode = mode;
			if remote {
				config.remote_agent_identity = Some(
					serde_json::from_value(serde_json::json!({
						"endpoint":"http://invalid.example/directory"
					}))
					.unwrap(),
				);
			}
			let audit = Arc::new(InMemoryAuditSink::default());
			let result =
				evaluate_with_audit_async(Arc::new(config), action.clone(), None, audit.clone()).await;
			assert_eq!(result.is_ok(), mode != SecurityMode::Enforce);
			let events = audit.events();
			assert!(!events.is_empty());
			assert!(
				events
					.iter()
					.all(|event| event.request_id == "awaited" && event.decision == DecisionEffect::Deny)
			);
		}
	}
	let mut config = allowed();
	config.required_audit = Some(required_audit::RequiredAuditConfig {
		action_types: vec![security_types::ActionType::ModelInvoke],
	});
	let audit = Arc::new(InMemoryAuditSink::default());
	assert!(
		evaluate_with_audit_async(Arc::new(config), action, None, audit.clone())
			.await
			.is_err()
	);
	assert!(
		audit
			.events()
			.iter()
			.any(|event| event.policy_id.as_deref() == Some("security:required-audit-unavailable"))
	);
}

#[test]
fn normalized_tool_list_keeps_transport_egress_constraints() {
	let egress: DataEgressConfig = serde_json::from_value(serde_json::json!({
		"classification":"restricted", "toolDestinations":["db/read"]
	}))
	.unwrap();
	let action = security_pipeline::tool_list("internal", Default::default(), "db");
	assert!(egress.permits(&action, "db"));
	assert!(!egress.permits(&action, "foreign-db"));
	let invoke =
		security_pipeline::tool_invoke_for_identity("internal", Default::default(), "delete");
	assert!(!egress.permits(&invoke, "db/delete"));
}

#[tokio::test]
async fn awaited_tool_requires_valid_composition_and_durable_audit() {
	let action =
		security_pipeline::tool_invoke_for_identity("tool-await", Default::default(), "delete");
	for mode in ["enforce", "audit", "shadow"] {
		let config = serde_json::from_value(serde_json::json!({
			"mode":mode,"policies":[{"id":"allow","enabled":true,"effect":"allow"}],
			"requiredToolApprovals":[{"toolName":"delete"}],
			"capabilityBroker":{"issueEndpoint":"http://invalid.example/issue"}
		}))
		.unwrap();
		let audit = Arc::new(InMemoryAuditSink::default());
		let result = authorize_tool_with_capability_with_audit_async(
			Arc::new(config),
			action.clone(),
			serde_json::json!({"record":42}),
			audit.clone(),
		)
		.await;
		if mode == "enforce" {
			assert!(result.is_err());
		} else {
			assert_eq!(result.unwrap(), None);
		}
		assert!(
			audit
				.events()
				.iter()
				.all(|event| event.policy_id.as_deref() != Some("security:capability"))
		);
	}
	let config = serde_json::from_value(serde_json::json!({
		"mode":"enforce","policies":[{"id":"allow","enabled":true,"effect":"allow"}],
		"requiredAudit":{"actionTypes":["toolInvoke"]}
	}))
	.unwrap();
	let audit = Arc::new(InMemoryAuditSink::default());
	assert!(
		authorize_tool_with_capability_with_audit_async(
			Arc::new(config),
			action,
			serde_json::json!({}),
			audit.clone()
		)
		.await
		.is_err()
	);
	assert!(
		audit
			.events()
			.iter()
			.any(|event| event.policy_id.as_deref() == Some("security:required-audit-unavailable"))
	);
}

#[test]
fn retry_charges_one_logical_call_but_each_attempt_and_releases_concurrency() {
	use execution_budget::{
		BudgetError, CallKind, ExecutionBudgetConfig, ExecutionBudgetStore,
		InMemoryExecutionBudgetStore, LogicalCharge,
	};
	let config: ExecutionBudgetConfig = serde_json::from_value(serde_json::json!({
		"namespace":uuid::Uuid::new_v4().to_string(), "maxModelCalls":1,"maxToolCalls":1,
		"maxAgentCalls":1,"maxAttempts":2,"maxConcurrent":1
	}))
	.unwrap();
	let identity = security_pipeline::GatewayIdentity {
		user_id: Some("alice".into()),
		tenant_id: Some("tenant-a".into()),
		..Default::default()
	};
	let owner =
		identity_binding::VerifiedOwner::from_identity(&identity, "https://issuer.example").unwrap();
	let store = InMemoryExecutionBudgetStore::default();
	let ledger = store
		.create(&config, owner, "configuration".into())
		.unwrap();
	let logical = LogicalCharge::default();
	let first = ledger.reserve(CallKind::Model, &logical).unwrap();
	assert!(matches!(
		ledger.reserve(CallKind::Model, &logical),
		Err(BudgetError::Concurrency)
	));
	assert_eq!(ledger.usage().unwrap().attempts, 1);
	drop(first);
	let retry = ledger.reserve(CallKind::Model, &logical).unwrap();
	let usage = ledger.usage().unwrap();
	assert_eq!(
		(usage.model_calls, usage.attempts, usage.concurrent),
		(1, 2, 1)
	);
	drop(retry);
	assert_eq!(ledger.usage().unwrap().concurrent, 0);
	assert!(matches!(
		ledger.reserve(CallKind::Model, &logical),
		Err(BudgetError::Attempts)
	));
	assert_eq!(ledger.usage().unwrap().model_calls, 1);
}

#[test]
fn budget_admission_preserves_namespace_owner_and_cancelled_capacity() {
	use execution_budget::{
		BudgetError, ExecutionBudgetConfig, ExecutionBudgetStore, InMemoryExecutionBudgetStore,
	};
	let mut config: ExecutionBudgetConfig = serde_json::from_value(serde_json::json!({
		"namespace":"first", "maxContexts":2,"maxContextsPerOwner":1,
		"maxModelCalls":1,"maxToolCalls":1,"maxAttempts":1,"maxConcurrent":1
	}))
	.unwrap();
	let owner = |user: &str| {
		identity_binding::VerifiedOwner::from_identity(
			&security_pipeline::GatewayIdentity {
				user_id: Some(user.into()),
				tenant_id: Some("tenant".into()),
				..Default::default()
			},
			"issuer",
		)
		.unwrap()
	};
	let store = Arc::new(InMemoryExecutionBudgetStore::default());
	let first = store
		.create(&config, owner("alice"), "config".into())
		.unwrap();
	first.cancel().unwrap();
	assert!(matches!(
		store.create(&config, owner("alice"), "config".into()),
		Err(BudgetError::Capacity)
	));
	let second = store
		.create(&config, owner("bob"), "config".into())
		.unwrap();
	assert!(matches!(
		store.create(&config, owner("carol"), "config".into()),
		Err(BudgetError::Capacity)
	));
	store
		.resolve(second.id(), &config, &owner("bob"), "config")
		.unwrap();
	config.namespace = "second".into();
	assert!(matches!(
		store.resolve(second.id(), &config, &owner("bob"), "config"),
		Err(BudgetError::InvalidContext)
	));
	std::thread::scope(|scope| {
		let attempts: Vec<_> = (0..8)
			.map(|_| {
				scope.spawn(|| {
					store
						.create(&config, owner("alice"), "config".into())
						.is_ok()
				})
			})
			.collect();
		assert_eq!(
			attempts
				.into_iter()
				.map(|thread| thread.join().unwrap())
				.filter(|ok| *ok)
				.count(),
			1
		);
	});
}

#[tokio::test]
async fn config_authorizer_awaited_mapping_matches_sync_modes_and_denials() {
	let action =
		security_pipeline::knowledge_retrieve_for_identity("rag-mapping", Default::default(), "docs");
	for mode in ["enforce", "audit", "shadow"] {
		for effect in ["allow", "deny"] {
			let config = serde_json::from_value(
				serde_json::json!({"mode":mode,"policies":[{"id":"rule","enabled":true,"effect":effect}]}),
			)
			.unwrap();
			let authorizer = SecurityConfigAuthorizer::new(Arc::new(config));
			assert_eq!(
				authorizer.decide(&action),
				authorizer.decide_async(&action).await
			);
		}
	}
}

/// A disk acknowledgement held by the fixture, with a timeout so a regression that
/// blocks the current-thread executor fails instead of hanging the test process.
struct WaitingAudit {
	wait_required: bool,
	fail: bool,
	started: tokio::sync::Notify,
	finished: tokio::sync::Notify,
	release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
	waiting: std::sync::atomic::AtomicBool,
	committed: std::sync::atomic::AtomicBool,
}
impl WaitingAudit {
	fn wait(&self) -> Result<(), String> {
		use std::sync::atomic::Ordering;
		self.waiting.store(true, Ordering::SeqCst);
		self.started.notify_one();
		let released = self
			.release
			.lock()
			.unwrap()
			.recv_timeout(std::time::Duration::from_secs(2))
			.is_ok();
		let committed = released && !self.fail;
		self.committed.store(committed, Ordering::SeqCst);
		self.finished.notify_one();
		if committed {
			Ok(())
		} else {
			Err("fixture persistence failure".into())
		}
	}
}
impl AuditSink for WaitingAudit {
	fn record(&self, _: SecurityEvent) {
		if !self.wait_required && !self.waiting.load(std::sync::atomic::Ordering::SeqCst) {
			let _ = self.wait();
		}
	}
	fn record_required(&self, _: SecurityEvent) -> Result<(), String> {
		self.wait()
	}
}
fn waiting_audit(
	required: bool,
	fail: bool,
) -> (
	Arc<WaitingAudit>,
	std::sync::mpsc::Sender<()>,
	Arc<SecurityConfig>,
) {
	let (release, receiver) = std::sync::mpsc::channel();
	let audit = Arc::new(WaitingAudit {
		wait_required: required,
		fail,
		started: Default::default(),
		finished: Default::default(),
		release: std::sync::Mutex::new(receiver),
		waiting: Default::default(),
		committed: Default::default(),
	});
	let mut config = allowed();
	if required {
		config.required_audit = Some(required_audit::RequiredAuditConfig {
			action_types: vec![security_types::ActionType::ModelInvoke],
		});
	}
	(audit, release, Arc::new(config))
}

#[tokio::test(flavor = "current_thread")]
async fn local_durable_audit_yields_executor_and_required_allow_waits_for_commit() {
	use std::sync::atomic::Ordering;
	for (required, fail) in [(false, false), (true, false), (true, true)] {
		let (audit, release, config) = waiting_audit(required, fail);
		let action = security_pipeline::model_invoke_for_identity("disk", Default::default(), "local");
		let evaluation = tokio::spawn(evaluate_with_audit_async(
			config,
			action,
			None,
			audit.clone(),
		));
		tokio::time::timeout(
			std::time::Duration::from_millis(250),
			audit.started.notified(),
		)
		.await
		.expect("disk work blocked the executor");
		tokio::time::sleep(std::time::Duration::from_millis(5)).await;
		assert!(
			!evaluation.is_finished(),
			"Allow returned before persistence"
		);
		assert!(!audit.committed.load(Ordering::SeqCst));
		release.send(()).unwrap();
		let result = evaluation.await.unwrap();
		assert_eq!(result.is_ok(), !fail);
		assert_eq!(audit.committed.load(Ordering::SeqCst), !fail);
		if fail {
			assert!(matches!(result, Err(GatewayError::Denied(ref decision))
				if decision.policy_id.as_deref() == Some("security:required-audit-unavailable")));
		}
	}
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_required_audit_waiter_cannot_resume_execution_after_commit() {
	use std::sync::atomic::{AtomicBool, Ordering};
	let (audit, release, config) = waiting_audit(true, false);
	let forwarded = Arc::new(AtomicBool::new(false));
	let forward = forwarded.clone();
	let sink = audit.clone();
	let waiter = tokio::spawn(async move {
		let action =
			security_pipeline::model_invoke_for_identity("cancel", Default::default(), "local");
		evaluate_with_audit_async(config, action, None, sink).await?;
		forward.store(true, Ordering::SeqCst);
		Ok::<_, GatewayError>(())
	});
	tokio::time::timeout(
		std::time::Duration::from_millis(250),
		audit.started.notified(),
	)
	.await
	.unwrap();
	waiter.abort();
	assert!(waiter.await.unwrap_err().is_cancelled());
	assert!(!audit.committed.load(Ordering::SeqCst));
	release.send(()).unwrap();
	tokio::time::timeout(std::time::Duration::from_secs(1), audit.finished.notified())
		.await
		.unwrap();
	assert!(audit.committed.load(Ordering::SeqCst));
	assert!(!forwarded.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "current_thread")]
async fn local_blocking_audit_shares_worker_admission_and_fails_closed_when_full() {
	struct BlockingSink(InMemoryAuditSink);
	impl AuditSink for BlockingSink {
		fn record(&self, event: SecurityEvent) {
			self.0.record(event);
		}
	}
	let mut held = Vec::new();
	tokio::time::timeout(std::time::Duration::from_secs(1), async {
		while held.len() < 32 {
			if let Ok(permit) = remote_worker::reserve() {
				held.push(permit);
			} else {
				tokio::task::yield_now().await;
			}
		}
	})
	.await
	.unwrap();
	let sink = Arc::new(BlockingSink(InMemoryAuditSink::default()));
	let config = Arc::new(allowed());
	let action = security_pipeline::model_invoke_for_identity("full", Default::default(), "local");
	assert!(matches!(
		evaluate_with_audit_async(config.clone(), action.clone(), None, sink.clone()).await,
		Err(GatewayError::Denied(_))
	));
	assert_eq!(
		sink.0.events().last().unwrap().decision,
		DecisionEffect::Deny
	);
	drop(held);
	assert!(
		evaluate_with_audit_async(config, action, None, sink)
			.await
			.is_ok()
	);
}
