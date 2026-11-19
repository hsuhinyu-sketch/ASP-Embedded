//! Explicit offline import. Reuse journal replay and domain rules; never merge live authorities.
use super::*;
use crate::{SecurityConfig, context_store::LocalSecurityContextStore};
use base64::Engine;
use security_rag::lifecycle::{DocumentLifecycleConfig, DocumentLifecycleStore};
use serde::{Deserialize, Serialize};

/// Both security declarations are required: changing storage may rebind the configuration
/// fingerprint, but cannot change identity, policy, lifetime, capacity or destination constraints.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportConfig {
	pub source_security: SecurityConfig,
	pub target_security: SecurityConfig,
	pub documents: DocumentLifecycleConfig,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
	pub documents: usize,
	pub contexts: usize,
}

fn fingerprint(config: &SecurityConfig) -> Result<String, String> {
	config
		.configuration_digest()
		.map(|digest| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

pub async fn import(config: ImportConfig) -> Result<ImportReport, String> {
	config.source_security.validate_composition()?;
	config.target_security.validate_composition()?;
	config.documents.validate()?;
	let source = config
		.source_security
		.cross_component
		.as_ref()
		.ok_or("missing source crossComponent")?;
	let target = config
		.target_security
		.cross_component
		.as_ref()
		.ok_or("missing target crossComponent")?;
	let journal = source
		.storage
		.clone()
		.ok_or("source must use a Context journal")?;
	let sqlite = target
		.sqlite
		.clone()
		.ok_or("target must explicitly select SQLite")?;
	if source.sqlite.is_some()
		|| target.storage.is_some()
		|| config.documents.namespace != sqlite.namespace
		|| config.documents.max_documents != sqlite.max_documents
	{
		return Err("source/target storage declarations do not match".into());
	}
	let mut equivalent = config.source_security.clone();
	let flow = equivalent.cross_component.as_mut().expect("checked");
	flow.storage = None;
	flow.sqlite = Some(sqlite.clone());
	if !equivalent
		.same_configuration(&config.target_security)
		.map_err(|_| "invalid security declaration")?
	{
		return Err(
			"migration can change only Context storage; all security controls must remain identical"
				.into(),
		);
	}
	let old_fingerprint = fingerprint(&config.source_security)?;
	let new_fingerprint = fingerprint(&config.target_security)?;
	let namespace = source.namespace.clone();
	let document_config = config.documents;
	// Production replay owns exclusive source locks until the destination has closed. Full or
	// read-only journals are not appended to; malformed transitions are not repaired or skipped.
	let (contexts, documents, authority, metadata, mut snapshots, highwater) =
		tokio::task::spawn_blocking(move || {
			let contexts = LocalSecurityContextStore::open_for_import(journal, &namespace)?;
			let documents = DocumentLifecycleStore::open_for_import(document_config)?;
			let (authority, metadata, document_water) = documents.import_records()?;
			let (bound_authority, snapshots, context_water) = contexts.import_records()?;
			if bound_authority.as_deref() != Some(authority.as_str()) {
				return Err("source journals have different document authorities".into());
			}
			Ok::<_, String>((
				contexts,
				documents,
				authority,
				metadata,
				snapshots,
				document_water.max(context_water),
			))
		})
		.await
		.map_err(|_| "source replay unavailable")??;
	if metadata.len() > sqlite.max_documents || snapshots.len() > sqlite.max_contexts {
		return Err("source state exceeds destination capacity".into());
	}
	for snapshot in &mut snapshots {
		if snapshot.binding.fingerprint != old_fingerprint
			|| snapshot.document_authority.as_deref() != Some(authority.as_str())
			|| snapshot.documents.iter().any(|r| r.authority != authority)
		{
			return Err("source Context does not match the declared security/document authority".into());
		}
		// Preserve ID, owner, issuance/expiry, revoked flag, classification and pinned versions.
		snapshot.binding.fingerprint.clone_from(&new_fingerprint);
	}
	let store = SqliteRagStore::open_inner(sqlite, true).await?;
	let result = async {
		let mut db = store.db.lock().await;
		let mut tx = db
			.begin()
			.await
			.map_err(|_| "destination transaction unavailable")?;
		sqlx::query("UPDATE asp_rag_meta SET authority=?,highwater=MAX(highwater,?) WHERE id=1")
			.bind(&authority)
			.bind(highwater)
			.execute(&mut *tx)
			.await
			.map_err(|_| "cannot import authority")?;
		for meta in &metadata {
			put_document(&mut tx, meta)
				.await
				.map_err(|_| "cannot import documents")?;
		}
		for snapshot in &snapshots {
			put_context(&mut tx, snapshot)
				.await
				.map_err(|_| "cannot import Context state")?;
		}
		// Recovery validates the same representation as a normal restart, including stale/revoked
		// references (retained, never revived). It does not turn them into valid authorizations.
		let (_, deadlines) = recover(&mut tx, &store.config).await?;
		let committed = commit(tx).await;
		db.after_commit(committed)
			.await
			.map_err(|_| "import commit unavailable; inspect destination before retry")?;
		db.deadlines = deadlines;
		Ok::<_, String>(ImportReport {
			documents: metadata.len(),
			contexts: snapshots.len(),
		})
	}
	.await;
	// Do not report success until connection shutdown is confirmed. On failure no source is
	// deleted and no existing target is retried/merged, including an unknown-commit outcome.
	store
		.close()
		.await
		.map_err(|_| "import close unavailable; inspect destination before retry")?;
	drop((contexts, documents));
	result
}
