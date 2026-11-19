#![cfg(feature = "rag-sqlite")]
use security_integration_runtime::{
	context_store::{ContextBinding, ContextError},
	identity_binding::VerifiedOwner,
	rag_sqlite::{SqliteRagConfig, SqliteRagStore},
};
use security_pipeline::GatewayIdentity;
use security_rag::{
	IndexedDocument, SourceOrigin, TrustedChunkAccess,
	lifecycle::{
		DocumentLifecycleConfig, DocumentLifecycleStore, DocumentMetadata, DocumentMutation,
		DocumentState,
	},
};
use security_types::{DataClassification, DocumentVersion};
use sqlx::{Connection, Executor};
use std::{
	fs,
	path::PathBuf,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	time::Duration,
};

struct Directory(PathBuf);
impl Directory {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!("rag-sqlite-backend-{}", uuid::Uuid::new_v4()));
		let mut builder = fs::DirBuilder::new();
		#[cfg(unix)]
		{
			use std::os::unix::fs::DirBuilderExt;
			builder.mode(0o700);
		}
		builder.create(&path).unwrap();
		Self(path)
	}
	fn config(&self) -> SqliteRagConfig {
		SqliteRagConfig {
			path: self.0.join("state.sqlite"),
			namespace: "knowledge".into(),
			max_documents: 16,
			max_contexts: 16,
			max_database_bytes: 1_048_576,
			busy_timeout_millis: 100,
		}
	}
	fn journal(&self, name: &str) -> security_audit::StateJournalConfig {
		security_audit::StateJournalConfig {
			path: self.0.join(name),
			max_bytes: 1_048_576,
		}
	}
}
impl Drop for Directory {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
fn binding() -> ContextBinding {
	ContextBinding {
		owner: VerifiedOwner::from_identity(
			&GatewayIdentity {
				user_id: Some("alice".into()),
				tenant_id: Some("tenant-a".into()),
				client_id: Some("client-a".into()),
				..Default::default()
			},
			"https://issuer.example",
		)
		.unwrap(),
		namespace: "knowledge".into(),
		fingerprint: "config-v1".into(),
	}
}
fn document() -> IndexedDocument {
	IndexedDocument {
		tenant_id: "tenant-a".into(),
		corpus_id: "docs".into(),
		document_id: "guide".into(),
		source_uri: "file:///guide".into(),
		source_hash: "a".repeat(64),
		source_origin: SourceOrigin::Submitted,
		content: "private knowledge".into(),
		labels: vec![],
		classification: DataClassification::Restricted,
		classification_source: "trusted".into(),
	}
}
fn access() -> TrustedChunkAccess {
	TrustedChunkAccess {
		allowed_users: vec!["alice".into()],
		..Default::default()
	}
}
fn reference(meta: &DocumentMetadata) -> DocumentVersion {
	DocumentVersion {
		key: meta.key.clone(),
		authority: meta.authority.clone(),
		revision: meta.revision,
	}
}
async fn seeded(config: SqliteRagConfig) -> (SqliteRagStore, String, DocumentMetadata) {
	let store = SqliteRagStore::open(config).await.unwrap();
	let mut meta = store.begin_index(&document(), access()).await.unwrap();
	assert!(
		store
			.issue_documents(
				binding(),
				60,
				DataClassification::Restricted,
				vec![reference(&meta)]
			)
			.await
			.is_err()
	);
	store.activate(&meta.key, meta.revision).await.unwrap();
	meta.state = DocumentState::Active;
	let id = store
		.issue_documents(
			binding(),
			60,
			DataClassification::Restricted,
			vec![reference(&meta)],
		)
		.await
		.unwrap();
	(store, id, meta)
}
async fn external(path: &std::path::Path) -> sqlx::SqliteConnection {
	sqlx::SqliteConnection::connect_with(&sqlx::sqlite::SqliteConnectOptions::new().filename(path))
		.await
		.unwrap()
}
fn equivalent(mut jsonl: DocumentMetadata, sqlite: &DocumentMetadata) {
	jsonl.authority = sqlite.authority.clone();
	assert_eq!(jsonl, *sqlite);
}

#[tokio::test]
async fn document_transitions_match_existing_journal_and_never_resurrect() {
	let dir = Directory::new();
	let sql = SqliteRagStore::open(dir.config()).await.unwrap();
	let journal = DocumentLifecycleStore::open(DocumentLifecycleConfig {
		namespace: "knowledge".into(),
		storage: dir.journal("documents.jsonl"),
		max_documents: 16,
	})
	.unwrap();
	let mut a = journal.begin_index(&document(), access()).unwrap();
	let mut b = sql.begin_index(&document(), access()).await.unwrap();
	equivalent(a.clone(), &b);
	// Re-indexing supersedes the pending content and makes the previous activation stale.
	let stale = b.revision;
	a = journal.begin_index(&document(), access()).unwrap();
	b = sql.begin_index(&document(), access()).await.unwrap();
	equivalent(a.clone(), &b);
	assert!(journal.activate(&a.key, stale).is_err());
	assert_eq!(sql.activate(&b.key, stale).await, Err(ContextError::Denied));
	journal.activate(&a.key, a.revision).unwrap();
	sql.activate(&b.key, b.revision).await.unwrap();
	for mutation in [
		DocumentMutation::Acl {
			access: TrustedChunkAccess {
				allowed_users: vec!["bob".into()],
				..Default::default()
			},
		},
		DocumentMutation::Revoke,
		DocumentMutation::Delete,
		DocumentMutation::Delete,
	] {
		a = journal
			.mutate(&a.key, a.revision, mutation.clone())
			.unwrap();
		b = sql.mutate(&b.key, b.revision, mutation).await.unwrap();
		equivalent(a.clone(), &b);
		assert!(
			journal
				.mutate(&a.key, a.revision - 1, DocumentMutation::Delete)
				.is_err()
		);
		assert_eq!(
			sql
				.mutate(&b.key, b.revision - 1, DocumentMutation::Delete)
				.await,
			Err(ContextError::Denied)
		);
	}
	assert!(journal.begin_index(&document(), access()).is_err());
	assert!(sql.begin_index(&document(), access()).await.is_err());
	assert!(
		sql
			.mutate(&b.key, b.revision, DocumentMutation::Revoke)
			.await
			.is_err()
	);
	let authority = sql.authority_id().to_owned();
	sql.close().await.unwrap();
	let sql = SqliteRagStore::open(dir.config()).await.unwrap();
	assert_eq!(sql.authority_id(), authority);
	equivalent(a, &sql.get_document(&b.key).await.unwrap());
	sql.close().await.unwrap();
}
#[tokio::test]
async fn context_binding_monotonic_classification_and_revocation_survive_reopen() {
	let dir = Directory::new();
	let (store, id, meta) = seeded(dir.config()).await;
	for field in [
		"tenant",
		"user",
		"agent",
		"client",
		"delegation",
		"issuer",
		"namespace",
		"config",
	] {
		let mut foreign = binding();
		let mut identity = foreign.owner.identity();
		let mut issuer = "https://issuer.example";
		match field {
			"tenant" => identity.tenant_id = Some("tenant-b".into()),
			"user" => identity.user_id = Some("bob".into()),
			"agent" => identity.agent_id = Some("agent-b".into()),
			"client" => identity.client_id = Some("other".into()),
			"delegation" => identity.delegation_id = Some("other".into()),
			"issuer" => issuer = "https://other.example",
			"namespace" => foreign.namespace = "other".into(),
			_ => foreign.fingerprint = "config-v2".into(),
		}
		foreign.owner = VerifiedOwner::from_identity(&identity, issuer).unwrap();
		assert_eq!(
			store.classification(&id, &foreign).await,
			Err(ContextError::Denied)
		);
		assert_eq!(store.revoke(&id, &foreign).await, Err(ContextError::Denied));
	}
	let other = store
		.issue_documents(
			binding(),
			60,
			DataClassification::Public,
			vec![reference(&meta)],
		)
		.await
		.unwrap();
	store
		.elevate_documents(&other, &binding(), DataClassification::Restricted, vec![])
		.await
		.unwrap();
	store
		.elevate_documents(&other, &binding(), DataClassification::Public, vec![])
		.await
		.unwrap();
	store.revoke(&id, &binding()).await.unwrap();
	store.close().await.unwrap();
	let store = SqliteRagStore::open(dir.config()).await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	assert_eq!(
		store.classification(&other, &binding()).await,
		Ok(DataClassification::Restricted)
	);
	store.close().await.unwrap();
}
#[tokio::test]
async fn document_acl_revision_and_tenant_are_checked_in_context_transaction() {
	let dir = Directory::new();
	let (store, id, meta) = seeded(dir.config()).await;
	let denied = store
		.mutate(
			&meta.key,
			meta.revision,
			DocumentMutation::Acl {
				access: TrustedChunkAccess {
					allowed_users: vec!["bob".into()],
					..Default::default()
				},
			},
		)
		.await
		.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	assert_eq!(
		store
			.issue_documents(
				binding(),
				60,
				DataClassification::Public,
				vec![reference(&denied)]
			)
			.await,
		Err(ContextError::Denied)
	);
	let restored = store
		.mutate(
			&meta.key,
			denied.revision,
			DocumentMutation::Acl { access: access() },
		)
		.await
		.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	); // same ACL never revives an old revision
	let mut foreign = document();
	foreign.tenant_id = "tenant-b".into();
	foreign.document_id = "foreign".into();
	let m = store.begin_index(&foreign, access()).await.unwrap();
	store.activate(&m.key, m.revision).await.unwrap();
	assert_eq!(
		store
			.issue_documents(
				binding(),
				60,
				DataClassification::Public,
				vec![reference(&m)]
			)
			.await,
		Err(ContextError::Denied)
	);
	store
		.mutate(&meta.key, restored.revision, DocumentMutation::Revoke)
		.await
		.unwrap();
	store.close().await.unwrap();
	let store = SqliteRagStore::open(dir.config()).await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	store.close().await.unwrap();
}
#[tokio::test]
async fn context_count_is_bounded_and_expiry_is_not_renewed_by_restart() {
	let dir = Directory::new();
	let mut config = dir.config();
	config.max_contexts = 1;
	config.max_documents = 1;
	let store = SqliteRagStore::open(config.clone()).await.unwrap();
	let id = store
		.issue_documents(binding(), 1, DataClassification::Internal, vec![])
		.await
		.unwrap();
	assert_eq!(
		store
			.issue_documents(binding(), 1, DataClassification::Public, vec![])
			.await,
		Err(ContextError::Capacity)
	);
	store.begin_index(&document(), access()).await.unwrap();
	let mut extra = document();
	extra.document_id = "other".into();
	assert_eq!(
		store.begin_index(&extra, access()).await,
		Err(ContextError::Capacity)
	);
	store.close().await.unwrap();
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let store = SqliteRagStore::open(config).await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	);
	assert!(
		store
			.issue_documents(binding(), 1, DataClassification::Public, vec![])
			.await
			.is_ok()
	);
	store.close().await.unwrap();
}
#[tokio::test(flavor = "current_thread")]
async fn busy_failure_does_not_block_tokio_and_is_sticky() {
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	let mut blocker = external(&dir.config().path).await;
	blocker.execute("BEGIN IMMEDIATE").await.unwrap();
	let progress = Arc::new(AtomicBool::new(false));
	let observed = progress.clone();
	let heartbeat = tokio::spawn(async move {
		tokio::time::sleep(Duration::from_millis(5)).await;
		observed.store(true, Ordering::Release);
	});
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	assert!(progress.load(Ordering::Acquire));
	heartbeat.await.unwrap();
	blocker.execute("ROLLBACK").await.unwrap();
	blocker.close().await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
}
#[tokio::test]
async fn cancellation_while_sqlite_begin_is_waiting_does_not_disclose_or_poison_next_use() {
	let dir = Directory::new();
	let mut config = dir.config();
	config.busy_timeout_millis = 1000;
	let (store, id, _) = seeded(config).await;
	let store = Arc::new(store);
	let mut blocker = external(&dir.config().path).await;
	blocker.execute("BEGIN IMMEDIATE").await.unwrap();
	let call = tokio::spawn({
		let store = store.clone();
		let id = id.clone();
		async move { store.classification(&id, &binding()).await }
	});
	tokio::time::sleep(Duration::from_millis(10)).await;
	assert!(!call.is_finished());
	call.abort();
	assert!(call.await.unwrap_err().is_cancelled());
	blocker.execute("ROLLBACK").await.unwrap();
	blocker.close().await.unwrap();
	assert!(store.classification(&id, &binding()).await.is_ok());
	Arc::try_unwrap(store).ok().unwrap().close().await.unwrap();
}
#[tokio::test]
async fn competing_revision_updates_and_post_revocation_reads_are_serialized() {
	let dir = Directory::new();
	let (store, id, meta) = seeded(dir.config()).await;
	let store = Arc::new(store);
	let mut jobs = tokio::task::JoinSet::new();
	for _ in 0..8 {
		let store = store.clone();
		let key = meta.key.clone();
		jobs.spawn(async move { store.mutate(&key, 1, DocumentMutation::Revoke).await });
	}
	let mut successes = 0;
	while let Some(result) = jobs.join_next().await {
		if result.unwrap().is_ok() {
			successes += 1;
		}
	}
	assert_eq!(successes, 1);
	let mut reads = tokio::task::JoinSet::new();
	for _ in 0..16 {
		let store = store.clone();
		let id = id.clone();
		reads.spawn(async move { store.classification(&id, &binding()).await });
	}
	while let Some(result) = reads.join_next().await {
		assert_eq!(result.unwrap(), Err(ContextError::Denied));
	}
	Arc::try_unwrap(store).ok().unwrap().close().await.unwrap();
}
#[tokio::test]
async fn invalid_files_declarations_and_recovered_metadata_are_rejected() {
	let dir = Directory::new();
	SqliteRagStore::open(dir.config())
		.await
		.unwrap()
		.close()
		.await
		.unwrap();
	fs::write(&dir.config().path, b"not SQLite").unwrap();
	assert!(SqliteRagStore::open(dir.config()).await.is_err());
	assert_eq!(fs::read(&dir.config().path).unwrap(), b"not SQLite");
	for kind in [
		"clock",
		"authority",
		"payload",
		"expiry",
		"capacity",
		"namespace",
		"version",
	] {
		let dir = Directory::new();
		let (store, _, _) = seeded(dir.config()).await;
		store.close().await.unwrap();
		let mut connection = external(&dir.config().path).await;
		let query = match kind {
			"clock" => "UPDATE asp_rag_meta SET highwater=9223372036854775807",
			"authority" => "UPDATE asp_rag_meta SET authority='invalid'",
			"payload" => "UPDATE asp_rag_documents SET metadata='{}'",
			"expiry" => "UPDATE asp_rag_contexts SET expires_ms=1",
			"capacity" => "UPDATE asp_rag_meta SET max_contexts=999",
			"namespace" => "UPDATE asp_rag_meta SET namespace='other'",
			_ => "PRAGMA user_version=2",
		};
		connection.execute(query).await.unwrap();
		connection.close().await.unwrap();
		assert!(SqliteRagStore::open(dir.config()).await.is_err(), "{kind}");
	}
}
#[tokio::test]
async fn full_database_fails_closed_and_keeps_acknowledged_rows() {
	let dir = Directory::new();
	let mut config = dir.config();
	config.max_documents = 4096;
	let (store, id, original) = seeded(config.clone()).await;
	let mut accepted = 1;
	let mut failed = false;
	for n in 0..1024 {
		let mut large = document();
		large.document_id = format!("large-{n}");
		large.labels = vec!["x".repeat(256); 16];
		match store.begin_index(&large, access()).await {
			Ok(_) => accepted += 1,
			Err(ContextError::Unavailable) => {
				failed = true;
				break;
			},
			other => panic!("unexpected {other:?}"),
		}
	}
	assert!(failed);
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
	let store = SqliteRagStore::open(config).await.unwrap();
	assert!(store.classification(&id, &binding()).await.is_ok());
	assert_eq!(store.get_document(&original.key).await.unwrap(), original);
	store.close().await.unwrap();
	let mut connection = external(&dir.config().path).await;
	let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asp_rag_documents")
		.fetch_one(&mut connection)
		.await
		.unwrap();
	assert_eq!(count, accepted);
	connection.close().await.unwrap();
}
#[tokio::test]
async fn single_owner_and_replaced_path_fail_closed() {
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	assert!(SqliteRagStore::open(dir.config()).await.is_err());
	fs::rename(&dir.config().path, dir.0.join("old.sqlite")).unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	fs::rename(dir.0.join("old.sqlite"), &dir.config().path).unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
}
#[cfg(unix)]
#[tokio::test]
async fn insecure_permissions_symlinks_and_hardlinks_are_rejected() {
	use std::os::unix::fs::{PermissionsExt, symlink};
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	fs::set_permissions(&dir.config().path, fs::Permissions::from_mode(0o644)).unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
	assert!(SqliteRagStore::open(dir.config()).await.is_err());
	fs::set_permissions(&dir.config().path, fs::Permissions::from_mode(0o600)).unwrap();
	let alias = dir.0.join("alias.sqlite");
	symlink(&dir.config().path, &alias).unwrap();
	let mut config = dir.config();
	config.path = alias.clone();
	assert!(SqliteRagStore::open(config.clone()).await.is_err());
	fs::remove_file(&alias).unwrap();
	fs::hard_link(&dir.config().path, &alias).unwrap();
	assert!(SqliteRagStore::open(config).await.is_err());
}

#[tokio::test]
async fn authoritative_chunk_filter_replaces_untrusted_acl_and_rejects_stale_content() {
	let dir = Directory::new();
	let (store, _, meta) = seeded(dir.config()).await;
	let mut doc = document();
	doc.source_origin = SourceOrigin::Lifecycle {
		authority: meta.authority.clone(),
		version: meta.version,
		revision: meta.revision,
		origin: Box::new(SourceOrigin::Submitted),
	};
	let mut chunk = doc.to_chunk(
		"chunk",
		"text",
		1,
		TrustedChunkAccess {
			allow_tenant_authenticated: true,
			..Default::default()
		},
	);
	chunk.classification = DataClassification::Public;
	let subject = binding().owner.identity().into();
	let filtered = store
		.filter_chunks(&[chunk.clone()], &subject)
		.await
		.unwrap();
	assert_eq!(filtered.len(), 1);
	assert_eq!(filtered[0].classification, DataClassification::Restricted);
	assert_eq!(filtered[0].allowed_users, vec!["alice"]);
	assert!(!filtered[0].allow_tenant_authenticated);
	let mut other = binding().owner.identity();
	other.tenant_id = Some("tenant-b".into());
	assert!(
		store
			.filter_chunks(&[chunk.clone()], &other.into())
			.await
			.unwrap()
			.is_empty()
	);
	chunk.source_hash = "b".repeat(64);
	assert!(
		store
			.filter_chunks(&[chunk], &subject)
			.await
			.unwrap()
			.is_empty()
	);
	store.close().await.unwrap();
}
#[tokio::test]
async fn future_time_water_quarantines_live_store_even_after_external_repair() {
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	let mut connection = external(&dir.config().path).await;
	let water: i64 = sqlx::query_scalar("SELECT highwater FROM asp_rag_meta")
		.fetch_one(&mut connection)
		.await
		.unwrap();
	connection
		.execute("UPDATE asp_rag_meta SET highwater=9223372036854775807")
		.await
		.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	sqlx::query("UPDATE asp_rag_meta SET highwater=?")
		.bind(water)
		.execute(&mut connection)
		.await
		.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	connection.close().await.unwrap();
	store.close().await.unwrap();
}
#[tokio::test]
async fn repeated_reads_reclaim_wal_without_accumulating_a_read_history() {
	let dir = Directory::new();
	let (store, id, _) = seeded(dir.config()).await;
	for _ in 0..1024 {
		store.classification(&id, &binding()).await.unwrap();
	}
	let mut connection = external(&dir.config().path).await;
	let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asp_rag_contexts")
		.fetch_one(&mut connection)
		.await
		.unwrap();
	assert_eq!(count, 1);
	let wal = dir.0.join("state.sqlite-wal");
	assert!(fs::metadata(wal).unwrap().len() <= 1_048_576);
	connection.close().await.unwrap();
	store.close().await.unwrap();
}

#[test]
fn recovery_worker() {
	let Some(path) = std::env::var_os("AISP_RAG_SQLITE_CHILD") else {
		return;
	};
	let directory = Directory(PathBuf::from(path));
	let config = directory.config();
	// The parent owns cleanup; this child is killed before normal teardown.
	let rt = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	rt.block_on(async move {
		let (store, id, meta) = seeded(config.clone()).await;
		if std::env::var("AISP_RAG_SQLITE_MODE").unwrap() == "revoked" {
			store.revoke(&id, &binding()).await.unwrap();
			store
				.mutate(&meta.key, meta.revision, DocumentMutation::Revoke)
				.await
				.unwrap();
		}
		fs::write(config.path.with_extension("ready"), id).unwrap();
		std::future::pending::<()>().await;
	});
}
#[tokio::test]
async fn acknowledged_live_and_revoked_state_recover_after_sigkill() {
	for mode in ["live", "revoked"] {
		let dir = Directory::new();
		let mut child = std::process::Command::new(std::env::current_exe().unwrap())
			.args(["--exact", "recovery_worker", "--nocapture"])
			.env("AISP_RAG_SQLITE_CHILD", &dir.0)
			.env("AISP_RAG_SQLITE_MODE", mode)
			.stdout(std::process::Stdio::null())
			.stderr(std::process::Stdio::null())
			.spawn()
			.unwrap();
		let ready = dir.config().path.with_extension("ready");
		let deadline = std::time::Instant::now() + Duration::from_secs(10);
		while !ready.exists() {
			if let Some(status) = child.try_wait().unwrap() {
				panic!("recovery worker exited {status}");
			}
			if std::time::Instant::now() >= deadline {
				let _ = child.kill();
				let _ = child.wait();
				panic!("recovery worker timeout");
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
		child.kill().unwrap();
		child.wait().unwrap();
		let id = fs::read_to_string(ready).unwrap();
		let store = SqliteRagStore::open(dir.config()).await.unwrap();
		assert_eq!(
			store.classification(&id, &binding()).await,
			if mode == "live" {
				Ok(DataClassification::Restricted)
			} else {
				Err(ContextError::Denied)
			}
		);
		let key = reference(
			&store
				.get_document(&security_types::DocumentKey {
					tenant_id: "tenant-a".into(),
					corpus_id: "docs".into(),
					document_id: "guide".into(),
				})
				.await
				.unwrap(),
		)
		.key;
		if mode == "revoked" {
			assert_eq!(
				store.get_document(&key).await.unwrap().state,
				DocumentState::Revoked
			);
		}
		store.close().await.unwrap();
	}
}

#[tokio::test]
async fn missing_owner_and_truncated_database_quarantine_the_live_store() {
	for owner in [true, false] {
		let dir = Directory::new();
		let (store, id, _) = seeded(dir.config()).await;
		if owner {
			fs::remove_file(dir.0.join("state.sqlite.owner")).unwrap();
		} else {
			fs::OpenOptions::new()
				.write(true)
				.open(&dir.config().path)
				.unwrap()
				.set_len(0)
				.unwrap();
		}
		assert_eq!(
			store.classification(&id, &binding()).await,
			Err(ContextError::Unavailable)
		);
		store.close().await.unwrap();
	}
}

#[tokio::test]
async fn pinned_reader_that_prevents_wal_reclamation_fails_closed() {
	let dir = Directory::new();
	let mut config = dir.config();
	config.busy_timeout_millis = 20;
	let (store, id, _) = seeded(config.clone()).await;
	let mut reader = external(&config.path).await;
	reader.execute("BEGIN").await.unwrap();
	let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asp_rag_contexts")
		.fetch_one(&mut reader)
		.await
		.unwrap();
	let mut refused = false;
	for _ in 0..512 {
		// Force distinct persisted millisecond waters; a repeated identical UPDATE need not append.
		tokio::time::sleep(Duration::from_millis(2)).await;
		match store.classification(&id, &binding()).await {
			Ok(_) => {},
			Err(ContextError::Unavailable) => {
				refused = true;
				break;
			},
			other => panic!("unexpected {other:?}"),
		}
	}
	assert!(
		refused,
		"a pinned WAL reader must not permit indefinite history growth"
	);
	reader.execute("ROLLBACK").await.unwrap();
	reader.close().await.unwrap();
	assert_eq!(
		store.classification(&id, &binding()).await,
		Err(ContextError::Unavailable)
	);
	store.close().await.unwrap();
	let store = SqliteRagStore::open(config).await.unwrap();
	assert!(store.classification(&id, &binding()).await.is_ok());
	store.close().await.unwrap();
}

#[tokio::test]
async fn shared_domain_ports_enforce_the_same_document_revision_and_context_binding() {
	use security_integration_runtime::context_store::SecurityContextStore;
	use security_rag::lifecycle::DocumentLifecycle;
	let directory = Directory::new();
	let store = SqliteRagStore::open_shared(directory.config())
		.await
		.unwrap();
	let contexts: Arc<dyn SecurityContextStore> = store.clone();
	let documents: Arc<dyn DocumentLifecycle> = store.clone();
	let meta = documents.begin_index(&document(), access()).await.unwrap();
	documents.activate(&meta.key, meta.revision).await.unwrap();
	let id = contexts
		.clone()
		.issue_documents_async(
			binding(),
			60,
			16,
			DataClassification::Restricted,
			vec![reference(&meta)],
		)
		.await
		.unwrap();
	assert_eq!(
		contexts.classification(&id, &binding()),
		Err(ContextError::Unavailable),
		"sync callers cannot fall back or wait for SQL"
	);
	assert_eq!(
		contexts
			.clone()
			.classification_async(id.clone(), binding())
			.await
			.unwrap(),
		DataClassification::Restricted
	);
	let mut foreign = binding();
	foreign.fingerprint.push_str("-changed");
	assert_eq!(
		contexts
			.clone()
			.classification_async(id.clone(), foreign)
			.await,
		Err(ContextError::Denied)
	);
	documents
		.mutate(&meta.key, meta.revision, DocumentMutation::Revoke)
		.await
		.unwrap();
	assert_eq!(
		contexts.clone().classification_async(id, binding()).await,
		Err(ContextError::Denied)
	);
	assert!(
		documents
			.validate_documents(&binding().owner.identity().into(), &[reference(&meta)])
			.await
			.is_err()
	);
}

#[tokio::test]
async fn matching_generations_reuse_one_authority_and_conflicting_declarations_are_rejected() {
	let directory = Directory::new();
	let (first, second) = tokio::join!(
		SqliteRagStore::open_shared(directory.config()),
		SqliteRagStore::open_shared(directory.config())
	);
	let first = first.unwrap();
	let second = second.unwrap();
	assert!(Arc::ptr_eq(&first, &second));
	let id = first
		.issue_documents(binding(), 60, DataClassification::Internal, vec![])
		.await
		.unwrap();
	let mut conflict = directory.config();
	conflict.max_documents += 1;
	assert!(SqliteRagStore::open_shared(conflict).await.is_err());
	assert_eq!(
		second.classification(&id, &binding()).await.unwrap(),
		DataClassification::Internal
	);
	second.revoke(&id, &binding()).await.unwrap();
	assert_eq!(
		first.classification(&id, &binding()).await,
		Err(ContextError::Denied)
	);
}

fn import_fixture(
	dir: &Directory,
) -> (
	security_integration_runtime::rag_sqlite::migration::ImportConfig,
	ContextBinding,
	String,
	String,
	DocumentMetadata,
) {
	use base64::Engine;
	use security_integration_runtime::{
		SecurityConfig,
		context_store::{LocalSecurityContextStore, SecurityContextStore},
	};
	let source: SecurityConfig = serde_json::from_value(serde_json::json!({"mode":"enforce", "crossComponent": {
		"namespace":"knowledge", "maxContexts":16,
		"storage":dir.journal("source-contexts.jsonl"),
		"destinations":[{"classification":"public"},{"classification":"internal"},{"classification":"restricted"}]
	}})).unwrap();
	let mut target = source.clone();
	let target_flow = target.cross_component.as_mut().unwrap();
	target_flow.storage = None;
	target_flow.sqlite = Some(dir.config());
	let documents = DocumentLifecycleConfig {
		namespace: "knowledge".into(),
		storage: dir.journal("source-documents.jsonl"),
		max_documents: 16,
	};
	let docs = DocumentLifecycleStore::open(documents.clone()).unwrap();
	let mut meta = docs.begin_index(&document(), access()).unwrap();
	docs.activate(&meta.key, meta.revision).unwrap();
	meta.state = DocumentState::Active;
	let flow = source.cross_component.as_ref().unwrap();
	let contexts =
		LocalSecurityContextStore::open(flow.storage.clone().unwrap(), &flow.namespace).unwrap();
	contexts
		.register_document_validator(&flow.namespace, docs.clone())
		.unwrap();
	let mut binding = binding();
	binding.fingerprint =
		base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(source.configuration_digest().unwrap());
	let live = contexts
		.issue_documents(
			binding.clone(),
			60,
			16,
			DataClassification::Restricted,
			vec![reference(&meta)],
		)
		.unwrap();
	let revoked = contexts
		.issue_documents(
			binding.clone(),
			60,
			16,
			DataClassification::Restricted,
			vec![reference(&meta)],
		)
		.unwrap();
	contexts.revoke(&revoked, &binding).unwrap();
	drop((contexts, docs));
	let config = security_integration_runtime::rag_sqlite::migration::ImportConfig {
		source_security: source,
		target_security: target,
		documents,
	};
	(config, binding, live, revoked, meta)
}
#[tokio::test]
async fn offline_import_preserves_identity_revocation_deadlines_and_sources() {
	use base64::Engine;
	use security_integration_runtime::rag_sqlite::migration::import;
	let dir = Directory::new();
	let (config, old, live, revoked, meta) = import_fixture(&dir);
	let paths = [
		&config.documents.storage.path,
		&config
			.source_security
			.cross_component
			.as_ref()
			.unwrap()
			.storage
			.as_ref()
			.unwrap()
			.path,
	];
	let before: Vec<_> = paths.iter().map(|p| fs::read(p).unwrap()).collect();
	let mut new = old.clone();
	new.fingerprint = base64::engine::general_purpose::URL_SAFE_NO_PAD
		.encode(config.target_security.configuration_digest().unwrap());
	let report = import(config).await.unwrap();
	assert_eq!((report.documents, report.contexts), (1, 2));
	assert_eq!(
		before[0],
		fs::read(dir.0.join("source-documents.jsonl")).unwrap()
	);
	assert_eq!(
		before[1],
		fs::read(dir.0.join("source-contexts.jsonl")).unwrap()
	);
	let sql = SqliteRagStore::open(dir.config()).await.unwrap();
	assert_eq!(sql.authority_id(), meta.authority);
	assert_eq!(sql.get_document(&meta.key).await.unwrap(), meta);
	assert_eq!(
		sql.classification(&live, &new).await.unwrap(),
		DataClassification::Restricted
	);
	assert_eq!(
		sql.classification(&revoked, &new).await,
		Err(ContextError::Denied)
	);
	assert_eq!(
		sql.classification(&live, &old).await,
		Err(ContextError::Denied)
	);
	let mut foreign = new.clone();
	foreign.owner = binding().owner;
	let mut identity = foreign.owner.identity();
	identity.tenant_id = Some("other".into());
	foreign.owner = VerifiedOwner::from_identity(&identity, "https://issuer.example").unwrap();
	assert_eq!(
		sql.classification(&live, &foreign).await,
		Err(ContextError::Denied)
	);
	let mut connection = external(&dir.config().path).await;
	let raw: String = sqlx::query_scalar("SELECT snapshot FROM asp_rag_contexts WHERE id=?")
		.bind(&live)
		.fetch_one(&mut connection)
		.await
		.unwrap();
	let old_records = String::from_utf8(before[1].clone()).unwrap();
	let original: serde_json::Value = old_records
		.lines()
		.map(|s| serde_json::from_str::<serde_json::Value>(s).unwrap())
		.find_map(|v| (v["change"]["snapshot"]["id"] == live).then(|| v["change"]["snapshot"].clone()))
		.unwrap();
	let migrated: serde_json::Value = serde_json::from_str(&raw).unwrap();
	for field in [
		"id",
		"created_ms",
		"expires_ms",
		"ttl_seconds",
		"classification",
		"documents",
		"document_authority",
		"revoked",
	] {
		assert_eq!(migrated[field], original[field], "{field}");
	}
	connection.close().await.unwrap();
	sql.close().await.unwrap();
	let sql = SqliteRagStore::open(dir.config()).await.unwrap();
	assert_eq!(
		sql.classification(&revoked, &new).await,
		Err(ContextError::Denied)
	);
	sql.close().await.unwrap();
}
#[tokio::test]
async fn offline_import_rejects_security_changes_locks_and_repeated_destination() {
	use security_integration_runtime::{
		context_store::LocalSecurityContextStore, rag_sqlite::migration::import,
	};
	let dir = Directory::new();
	let (mut config, _, _, _, _) = import_fixture(&dir);
	config
		.target_security
		.cross_component
		.as_mut()
		.unwrap()
		.ttl_seconds = 120;
	assert!(
		import(config)
			.await
			.unwrap_err()
			.contains("only Context storage")
	);
	assert!(!dir.config().path.exists());
	let (config, _, _, _, _) = import_fixture(&dir);
	let source = config.source_security.cross_component.as_ref().unwrap();
	let held =
		LocalSecurityContextStore::open(source.storage.clone().unwrap(), &source.namespace).unwrap();
	assert!(import(config).await.is_err());
	assert!(!dir.config().path.exists());
	drop(held);
	let (config, _, _, _, _) = import_fixture(&dir);
	import(config).await.unwrap();
	let before = fs::read(&dir.config().path).unwrap();
	let (config, _, _, _, _) = import_fixture(&dir);
	assert!(
		import(config)
			.await
			.unwrap_err()
			.contains("new SQLite destination")
	);
	assert_eq!(before, fs::read(&dir.config().path).unwrap());
}
#[tokio::test]
async fn offline_import_rejects_corrupt_journals_and_foreign_authority_without_creating_target() {
	use security_integration_runtime::rag_sqlite::migration::import;
	let dir = Directory::new();
	let (config, _, _, _, _) = import_fixture(&dir);
	let mut file = fs::OpenOptions::new()
		.append(true)
		.open(&config.documents.storage.path)
		.unwrap();
	use std::io::Write;
	file.write_all(b"{\"partial\":").unwrap();
	drop(file);
	assert!(import(config).await.is_err());
	assert!(!dir.config().path.exists());
	let other = Directory::new();
	let (config, _, _, _, _) = import_fixture(&other);
	let another = Directory::new();
	let (mut foreign, _, _, _, _) = import_fixture(&another);
	foreign.documents = config.documents;
	assert!(
		import(foreign)
			.await
			.unwrap_err()
			.contains("different document authorities")
	);
	assert!(!another.config().path.exists());
}

#[tokio::test]
async fn offline_import_can_recover_a_full_journal_without_appending_a_checkpoint() {
	use security_integration_runtime::{
		context_store::LocalSecurityContextStore, rag_sqlite::migration::import,
	};
	use std::io::Write;
	let dir = Directory::new();
	let (config, _, _, _, _) = import_fixture(&dir);
	let flow = config.source_security.cross_component.as_ref().unwrap();
	let spec = flow.storage.as_ref().unwrap();
	let source = fs::read_to_string(&spec.path).unwrap();
	let mut event: serde_json::Value = serde_json::from_str(source.lines().last().unwrap()).unwrap();
	event["change"] = serde_json::json!({"kind":"Checkpoint"});
	let mut bytes = source.len() as u64;
	let mut file = fs::OpenOptions::new()
		.append(true)
		.open(&spec.path)
		.unwrap();
	loop {
		event["sequence"] = serde_json::json!(event["sequence"].as_u64().unwrap() + 1);
		let line = format!("{}\n", serde_json::to_string(&event).unwrap());
		if bytes + line.len() as u64 > spec.max_bytes {
			break;
		}
		file.write_all(line.as_bytes()).unwrap();
		bytes += line.len() as u64;
	}
	file.sync_all().unwrap();
	drop(file);
	let before = fs::read(&spec.path).unwrap();
	assert!(
		LocalSecurityContextStore::open(spec.clone(), &flow.namespace).is_err(),
		"the legacy opener needs another durable checkpoint"
	);
	assert_eq!(import(config).await.unwrap().contexts, 2);
	assert_eq!(
		before,
		fs::read(dir.0.join("source-contexts.jsonl")).unwrap()
	);
}
