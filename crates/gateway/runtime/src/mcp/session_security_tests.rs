use super::*;
use serde_json::json;

// Private fixture compiled only for tests; production constructors and visibility are unchanged.
pub(super) fn access() -> SessionAccess {
	let config: SecurityConfig = serde_json::from_value(json!({
		"mode":"enforce", "mcpSessions":{},
		"policies":[{"id":"allow", "enabled":true, "effect":"allow"}]
	}))
	.unwrap();
	let identity = GatewayIdentity {
		user_id: Some("alice".into()),
		tenant_id: Some("tenant-a".into()),
		client_id: Some("client-a".into()),
		..Default::default()
	};
	let owner = VerifiedOwner::from_identity(&identity, "https://issuer.example").unwrap();
	let revision = gateway_contracts::ConfigRevision::default().lease();
	let binding = Arc::new(SessionBinding {
		owner: owner.clone(),
		scope: "route-a".into(),
		created: Instant::now(),
		last_access: Mutex::new(Instant::now()),
		idle_ttl: Duration::from_secs(300),
		max_age: Duration::from_secs(600),
		revision: revision.clone(),
		closed: AtomicBool::new(false),
		_slot: reserve(&Arc::new(AtomicUsize::new(0)), 1).unwrap(),
		subscriptions: Default::default(),
		reverse: Default::default(),
		tasks: Default::default(),
		flow: None,
	});
	SessionAccess {
		limits: config.mcp_sessions.clone().unwrap(),
		config: Arc::new(config),
		owner,
		identity: identity.clone(),
		scope: "route-a".into(),
		expires: chrono::Utc::now().timestamp() + 300,
		revision,
		action: security_pipeline::mcp_session_for_identity("internal", identity, "use", "session"),
		binding: Some(binding),
		_stream: reserve(&Arc::new(AtomicUsize::new(0)), 1).unwrap(),
		flow: None,
		policies: super::super::rbac::McpAuthorizationSet::new(Vec::new().into()),
		legacy: None,
		authorization_request: Arc::new(http::Request::new(())),
	}
}

pub(super) fn context(access: &SessionAccess) -> super::super::upstream::IncomingRequestContext {
	let mut req = http::Request::new(());
	req.extensions_mut().insert(access.clone());
	req
		.extensions_mut()
		.insert(security_types::RequestContext::default());
	super::super::upstream::IncomingRequestContext::new(&req.into_parts().0)
}

#[tokio::test]
async fn session_checks_intersect_common_and_legacy_declarations() {
	let mut access = access();
	assert!(access.check().await.is_ok());
	assert!(access.check().await.is_ok());
	for rules in [
		json!([]),
		json!([
			{"id":"allow","enabled":true,"effect":"allow"},
			{"id":"deny-session","enabled":true,"effect":"deny","actionType":"mcpSessionOperation"}
		]),
	] {
		let legacy: security_pipeline::SecurityPipelineConfig =
			serde_json::from_value(json!({"policies":rules})).unwrap();
		access.legacy = Some(legacy.into());
		assert!(access.check().await.is_err());
		assert!(access.check().await.is_err());
	}
	let legacy: security_pipeline::SecurityPipelineConfig = serde_json::from_value(json!({
		"policies":[{"id":"allow","enabled":true,"effect":"allow"}]
	}))
	.unwrap();
	access.legacy = Some(legacy.into());
	assert!(access.check().await.is_ok());
	assert!(access.check().await.is_ok());
	Arc::make_mut(&mut access.config).pipeline.policies.clear();
	assert!(access.check().await.is_err());
	assert!(access.check().await.is_err());
}

#[tokio::test]
async fn session_rejects_foreign_owner_scope_expiry_and_closed_binding() {
	let access = access();
	assert!(access.check().await.is_ok());
	for field in ["user", "tenant", "client", "issuer", "scope"] {
		let mut foreign = access.clone();
		let mut identity = foreign.identity.clone();
		match field {
			"user" => identity.user_id = Some("bob".into()),
			"tenant" => identity.tenant_id = Some("other".into()),
			"client" => identity.client_id = Some("other".into()),
			"scope" => foreign.scope = "other".into(),
			_ => {},
		}
		foreign.owner = VerifiedOwner::from_identity(
			&identity,
			if field == "issuer" {
				"https://other.example"
			} else {
				"https://issuer.example"
			},
		)
		.unwrap();
		assert!(foreign.check().await.is_err(), "{field}");
	}
	let mut expired = access.clone();
	expired.expires = chrono::Utc::now().timestamp() - 1;
	assert!(expired.check().await.is_err());
	access
		.binding
		.as_ref()
		.unwrap()
		.closed
		.store(true, Ordering::Release);
	assert!(access.check().await.is_err());
}

#[tokio::test]
async fn configuration_invalidation_drops_pending_upstream_future() {
	struct OnDrop(Arc<AtomicBool>);
	impl Drop for OnDrop {
		fn drop(&mut self) {
			self.0.store(true, Ordering::Release);
		}
	}
	let mut access = access();
	let revision = gateway_contracts::ConfigRevision::default();
	access.revision = revision.lease();
	let dropped = Arc::new(AtomicBool::new(false));
	let upstream = async {
		let _lease = OnDrop(dropped.clone());
		std::future::pending::<Result<Response, ProxyError>>().await
	};
	let invalidate = async {
		tokio::task::yield_now().await;
		revision.invalidate();
	};
	let (result, ()) = tokio::join!(access.call(upstream), invalidate);
	assert!(result.is_err());
	assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test(start_paused = true)]
async fn idle_response_terminates_and_drops_upstream_on_timeout() {
	struct OnDrop(Arc<AtomicBool>);
	impl Drop for OnDrop {
		fn drop(&mut self) {
			self.0.store(true, Ordering::Release);
		}
	}
	let mut access = access();
	access.limits.stream_idle_seconds = 1;
	let dropped = Arc::new(AtomicBool::new(false));
	let lease = OnDrop(dropped.clone());
	let upstream =
		futures_util::stream::pending::<Result<bytes::Bytes, std::io::Error>>().map(move |item| {
			let _keep = &lease;
			item
		});
	let response = access
		.protect_response(Response::new(Body::from_stream(upstream)))
		.await
		.unwrap();
	assert!(
		crate::http::read_body_with_limit(response.into_body(), 1024)
			.await
			.is_err()
	);
	assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn notifications_do_not_lose_terminal_result_or_disclose_unrelated_progress() {
	let access = access();
	let context = context(&access);
	let request = serde_json::from_value(json!({"jsonrpc":"2.0","id":7,"method":"tools/call", "params":{"name":"echo","arguments":{},"_meta":{"progressToken":"mine"}}})).unwrap();
	let messages = [
		json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"other","progress":1}}),
		json!({"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"private log"}}),
		json!({"jsonrpc":"2.0","method":"notifications/tasks/status","params":{"taskId":"unrelated-task","status":"working","createdAt":"2026-10-29T00:00:00Z","lastUpdatedAt":"2026-10-29T00:00:00Z","ttl":60000}}),
		json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"mine","progress":2}}),
		json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"terminal"}]}}),
	];
	let stream = Messages::from_stream(futures_util::stream::iter(
		messages
			.into_iter()
			.map(|v| Ok(serde_json::from_value(v).unwrap())),
	));
	let values = protect_messages(stream, &context, Some(&request), "upstream")
		.await
		.try_collect::<Vec<_>>()
		.await
		.unwrap();
	assert_eq!(values.len(), 2);
	assert_eq!(
		serde_json::to_value(&values[0]).unwrap()["params"]["progressToken"],
		"mine"
	);
	assert_eq!(serde_json::to_value(&values[1]).unwrap()["id"], 7);
}

#[tokio::test(start_paused = true)]
async fn ignored_notifications_do_not_extend_idle_deadline() {
	let mut access = access();
	access.limits.stream_idle_seconds = 2;
	let context = context(&access);
	let stream = Messages::from_stream(futures_util::stream::unfold((), |_| async {
		tokio::time::sleep(Duration::from_secs(1)).await;
		Some((Ok(serde_json::from_value(json!({"jsonrpc":"2.0","method":"notifications/message", "params":{"level":"info","data":"ignored"}})).unwrap()), ()))
	}));
	let start = tokio::time::Instant::now();
	assert!(
		protect_messages(stream, &context, None, "upstream")
			.await
			.next()
			.await
			.unwrap()
			.is_err()
	);
	assert_eq!(start.elapsed(), Duration::from_secs(2));
}

#[tokio::test]
async fn checks_and_binding_do_not_count_as_activity_but_accepted_requests_do() {
	let mut access = access();
	let binding = access.binding.clone().unwrap();
	let before = Instant::now() - Duration::from_secs(100);
	*binding.last_access.lock().unwrap() = before;
	access.check().await.unwrap();
	access.check().await.unwrap();
	access.bind(binding.clone()).await.unwrap();
	assert!(
		access
			.call(async { Err(ProxyError::AuthorizationFailed) })
			.await
			.is_err()
	);
	assert_eq!(*binding.last_access.lock().unwrap(), before);
	access
		.call(async { Ok(Response::new(Body::empty())) })
		.await
		.unwrap();
	assert!(*binding.last_access.lock().unwrap() > before);
	*binding.last_access.lock().unwrap() = before;
	access
		.call(async {
			Ok(
				http::Response::builder()
					.status(http::StatusCode::ACCEPTED)
					.body(Body::empty())
					.unwrap(),
			)
		})
		.await
		.unwrap();
	assert!(*binding.last_access.lock().unwrap() > before);
}

#[tokio::test]
async fn only_authorized_correlated_messages_refresh_the_binding() {
	for case in ["accepted", "unrelated", "business-denied", "malformed"] {
		let mut access = access();
		if case == "business-denied" {
			Arc::make_mut(&mut access.config).pipeline.policies.push(
				serde_json::from_value(json!({
						"id":"deny-tool", "effect":"deny", "enabled":true, "actionType":"toolInvoke"
				}))
				.unwrap(),
			);
		}
		let binding = access.binding.clone().unwrap();
		let before = Instant::now() - Duration::from_secs(100);
		*binding.last_access.lock().unwrap() = before;
		let context = context(&access);
		let request = serde_json::from_value(json!({"jsonrpc":"2.0","id":7,"method":"tools/call", "params":{"name":"echo","arguments":{},"_meta":{"progressToken":"mine"}}})).unwrap();
		let message = match case {
			"unrelated" => {
				json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"other","progress":1}})
			},
			"malformed" => json!({"jsonrpc":"2.0","id":8,"result":{"content":[]}}),
			_ => {
				json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"mine","progress":1}})
			},
		};
		let messages = Messages::from_stream(futures_util::stream::iter([Ok(
			serde_json::from_value(message).unwrap(),
		)]));
		let result = protect_messages(messages, &context, Some(&request), "upstream")
			.await
			.next()
			.await;
		if case == "accepted" {
			assert!(result.unwrap().is_ok());
			assert!(*binding.last_access.lock().unwrap() > before);
		} else {
			if case == "unrelated" {
				assert!(result.is_none());
			} else {
				assert!(result.unwrap().is_err());
			}
			assert_eq!(*binding.last_access.lock().unwrap(), before, "{case}");
		}
	}
}

#[tokio::test]
async fn activity_cannot_revive_idle_old_foreign_revoked_or_denied_sessions() {
	for case in [
		"idle",
		"max-age",
		"owner",
		"closed",
		"revision",
		"credential",
		"policy",
	] {
		let mut access = access();
		let binding = Arc::get_mut(access.binding.as_mut().unwrap()).unwrap();
		binding.last_access = Mutex::new(Instant::now() - Duration::from_secs(100));
		match case {
			"idle" => binding.idle_ttl = Duration::from_secs(1),
			"max-age" => binding.created = Instant::now() - Duration::from_secs(601),
			"owner" => access.scope = "foreign".into(),
			"closed" => binding.closed.store(true, Ordering::Release),
			"revision" => {
				let revision = gateway_contracts::ConfigRevision::default();
				binding.revision = revision.lease();
				revision.invalidate();
			},
			"credential" => access.expires = 0,
			"policy" => Arc::make_mut(&mut access.config).pipeline.policies.clear(),
			_ => unreachable!(),
		}
		let binding = access.binding.as_ref().unwrap();
		let before = *binding.last_access.lock().unwrap();
		assert!(
			access
				.call(async {
					Ok(
						http::Response::builder()
							.status(http::StatusCode::ACCEPTED)
							.body(Body::empty())
							.unwrap(),
					)
				})
				.await
				.is_err(),
			"{case}"
		);
		assert_eq!(*binding.last_access.lock().unwrap(), before, "{case}");
	}
}

#[tokio::test]
async fn periodic_authorization_keeps_polling_storage_owner_and_withholds_denied_result() {
	for deny in [false, true] {
		let mut access = access();
		access.limits.reauthorize_seconds = 1;
		let transaction = Arc::new(tokio::sync::Mutex::new(()));
		let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
		let source = async {
			let _owner = transaction.lock().await;
			tokio::time::sleep(Duration::from_millis(1100)).await;
			completed.store(true, Ordering::Release);
			"protected bytes"
		};
		let result = access
			.checked_wait(
				source,
				tokio::time::Instant::now() + Duration::from_secs(3),
				|| {
					Box::pin(async {
						let _owner = transaction.lock().await;
						if deny && completed.load(Ordering::Acquire) {
							return Err(access.denial("revoked"));
						}
						Ok(())
					})
				},
			)
			.await;
		assert!(
			completed.load(Ordering::Acquire),
			"the pending reader must release its transaction"
		);
		if deny {
			assert!(result.is_err());
		} else {
			assert_eq!(result.unwrap(), "protected bytes");
		}
	}
}

#[cfg(feature = "security-rag-sqlite")]
#[tokio::test]
async fn sqlite_session_context_is_checked_natively_and_acknowledged_revocation_denies_use() {
	use security_integration_runtime::{
		context_store::ContextBinding,
		rag_sqlite::{SqliteRagConfig, SqliteRagStore},
	};
	let directory = std::env::temp_dir().join(format!("mcp-sqlite-context-{}", uuid::Uuid::new_v4()));
	let mut builder = std::fs::DirBuilder::new();
	#[cfg(unix)]
	{
		use std::os::unix::fs::DirBuilderExt;
		builder.mode(0o700);
	}
	builder.create(&directory).unwrap();
	let mut access = access();
	let mut config = (*access.config).clone();
	let sqlite = SqliteRagConfig {
		path: directory.join("rag.db"),
		namespace: "mcp-native".into(),
		max_documents: 16,
		max_contexts: 16,
		max_database_bytes: 1048576,
		busy_timeout_millis: 100,
	};
	config.cross_component = Some(serde_json::from_value(json!({"namespace":"mcp-native", "maxContexts":16,
		"sqlite":sqlite, "destinations":[{"classification":"public"},{"classification":"internal"},{"classification":"restricted"}]})).unwrap());
	config
		.cross_component
		.as_ref()
		.unwrap()
		.prepare_store_async()
		.await
		.unwrap();
	let store = SqliteRagStore::open_shared(sqlite).await.unwrap();
	let binding = ContextBinding {
		owner: access.owner.clone(),
		namespace: "mcp-native".into(),
		fingerprint: crate::security::configuration_fingerprint(&config).unwrap(),
	};
	let id = store
		.issue_documents(
			binding.clone(),
			60,
			security_types::DataClassification::Restricted,
			vec![],
		)
		.await
		.unwrap();
	let claims = crate::http::jwt::Claims { inner: serde_json::from_value(json!({"iss":"https://issuer.example", "sub":"alice", "tenantId":"tenant-a", "clientId":"client-a", "exp":access.expires})).unwrap(), jwt: "verified-extension".into() };
	let mut headers = http::HeaderMap::new();
	headers.insert(crate::security_flow::HEADER, id.parse().unwrap());
	let mut extensions = http::Extensions::new();
	extensions.insert(claims);
	let flow = crate::security_flow::prepare_async(&config, &headers, &extensions)
		.await
		.unwrap()
		.unwrap();
	Arc::get_mut(access.binding.as_mut().unwrap()).unwrap().flow = Some(flow.clone());
	access.flow = Some(flow);
	access.config = Arc::new(config);
	access.check().await.unwrap();
	// A provider/request gate may carry another Context than the Session gate. Both must pass.
	let second = store
		.issue_documents(
			binding.clone(),
			60,
			security_types::DataClassification::Restricted,
			vec![],
		)
		.await
		.unwrap();
	headers.insert(crate::security_flow::HEADER, second.parse().unwrap());
	let inherited = crate::security_flow::prepare_async(&access.config, &headers, &extensions)
		.await
		.unwrap()
		.unwrap();
	let mut request = http::Request::new(());
	request.extensions_mut().insert(access.clone());
	request.extensions_mut().insert(inherited);
	store.revoke(&second, &binding).await.unwrap();
	assert!(crate::mcp::dispatch::current_async(&request).await.is_err());
	drop(request);
	store.revoke(&id, &binding).await.unwrap();
	assert!(access.check().await.is_err());
	drop((access, store));
	std::fs::remove_dir_all(directory).unwrap();
}
