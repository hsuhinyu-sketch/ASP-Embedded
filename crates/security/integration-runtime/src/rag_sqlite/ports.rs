//! Domain ports share the same connection/transaction owner. Synchronous callers cannot block
//! a Tokio worker waiting for SQL; they must migrate to the async Context entry points.
use super::*;
use crate::context_store::{ContextFuture, SecurityContextStore};
use security_rag::lifecycle::DocumentLifecycle;
use std::sync::Arc;

impl SecurityContextStore for SqliteRagStore {
	fn issue(
		&self,
		_: ContextBinding,
		_: u64,
		_: usize,
		_: DataClassification,
	) -> Result<String, ContextError> {
		Err(ContextError::Unavailable)
	}
	fn classification(
		&self,
		_: &str,
		_: &ContextBinding,
	) -> Result<DataClassification, ContextError> {
		Err(ContextError::Unavailable)
	}
	fn elevate(
		&self,
		_: &str,
		_: &ContextBinding,
		_: DataClassification,
	) -> Result<(), ContextError> {
		Err(ContextError::Unavailable)
	}
	fn revoke(&self, _: &str, _: &ContextBinding) -> Result<(), ContextError> {
		Err(ContextError::Unavailable)
	}
	fn issue_documents_async(
		self: Arc<Self>,
		binding: ContextBinding,
		ttl: u64,
		capacity: usize,
		class: DataClassification,
		documents: Vec<DocumentVersion>,
	) -> ContextFuture<String> {
		Box::pin(async move {
			if capacity != self.config.max_contexts {
				return Err(ContextError::Denied);
			}
			SqliteRagStore::issue_documents(&self, binding, ttl, class, documents).await
		})
	}
	fn classification_async(
		self: Arc<Self>,
		id: String,
		binding: ContextBinding,
	) -> ContextFuture<DataClassification> {
		Box::pin(async move { SqliteRagStore::classification(&self, &id, &binding).await })
	}
	fn elevate_documents_async(
		self: Arc<Self>,
		id: String,
		binding: ContextBinding,
		class: DataClassification,
		documents: Vec<DocumentVersion>,
	) -> ContextFuture<()> {
		Box::pin(async move {
			SqliteRagStore::elevate_documents(&self, &id, &binding, class, documents).await
		})
	}
	fn revoke_async(self: Arc<Self>, id: String, binding: ContextBinding) -> ContextFuture<()> {
		Box::pin(async move { SqliteRagStore::revoke(&self, &id, &binding).await })
	}
}

fn storage_error(error: ContextError) -> String {
	format!("document authority rejected operation: {error:?}")
}

#[async_trait::async_trait]
impl DocumentLifecycle for SqliteRagStore {
	async fn begin_index(
		&self,
		document: &IndexedDocument,
		access: TrustedChunkAccess,
	) -> Result<DocumentMetadata, String> {
		SqliteRagStore::begin_index(self, document, access)
			.await
			.map_err(storage_error)
	}
	async fn activate(&self, key: &DocumentKey, revision: u64) -> Result<(), String> {
		SqliteRagStore::activate(self, key, revision)
			.await
			.map_err(storage_error)
	}
	async fn get(&self, key: &DocumentKey) -> Result<DocumentMetadata, String> {
		SqliteRagStore::get_document(self, key)
			.await
			.map_err(storage_error)
	}
	async fn mutate(
		&self,
		key: &DocumentKey,
		expected_revision: u64,
		mutation: DocumentMutation,
	) -> Result<DocumentMetadata, String> {
		SqliteRagStore::mutate(self, key, expected_revision, mutation)
			.await
			.map_err(storage_error)
	}
	async fn filter_chunks(
		&self,
		chunks: &[KnowledgeChunk],
		subject: &Subject,
	) -> Result<Vec<KnowledgeChunk>, String> {
		SqliteRagStore::filter_chunks(self, chunks, subject)
			.await
			.map_err(storage_error)
	}
	async fn validate_documents(
		&self,
		subject: &Subject,
		documents: &[DocumentVersion],
	) -> Result<(), String> {
		SqliteRagStore::validate_documents(self, subject, documents)
			.await
			.map_err(storage_error)
	}
}
