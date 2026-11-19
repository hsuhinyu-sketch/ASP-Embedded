use crate::context_store::validate_namespace;
use std::path::PathBuf;

/// Explicit joint Context/document state. This never imports or replaces JSONL.
/// max_database_bytes limits database pages, not total disk usage. WAL reclamation is separate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SqliteRagConfig {
	pub path: PathBuf,
	pub namespace: String,
	pub max_documents: usize,
	pub max_contexts: usize,
	pub max_database_bytes: u64,
	pub busy_timeout_millis: u64,
}
impl SqliteRagConfig {
	pub fn validate(&self) -> Result<(), String> {
		validate_namespace(&self.namespace)?;
		if !self.path.is_absolute()
			|| self.path.file_name().is_none()
			|| !(1..=4096).contains(&self.max_documents)
			|| !(1..=16384).contains(&self.max_contexts)
			|| !(1_048_576..=67_108_864).contains(&self.max_database_bytes)
			|| !(1..=5000).contains(&self.busy_timeout_millis)
		{
			return Err("invalid SQLite RAG path/capacity/busy timeout".into());
		}
		Ok(())
	}
}
