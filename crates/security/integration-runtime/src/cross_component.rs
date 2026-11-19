//! Administrator-owned cross-component data-flow contract. Context IDs are not credentials.
use crate::{DataClassification, DataEgressConfig};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossComponentConfig {
	/// A deployment-unique AI-system trust domain, shared by its RAG/LLM/Agent/MCP routes.
	pub namespace: String,
	#[serde(default = "ttl")]
	pub ttl_seconds: u64,
	#[serde(default = "capacity")]
	pub max_contexts: usize,
	/// Treat unproven request payloads as Restricted at the gateway's outbound boundary.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub restrict_untrusted_payloads: bool,
	/// Exactly one policy per class. Sensitive classes intersect all lower-class policies.
	pub destinations: Vec<DataEgressConfig>,
	/// Optional private single-writer journal; absent preserves process-local behavior.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub storage: Option<security_audit::StateJournalConfig>,
	/// Optional joint SQLite document/Context authority; mutually exclusive with `storage`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub sqlite: Option<crate::rag_storage::SqliteRagConfig>,
	#[serde(skip)]
	pub store: crate::context_store::ContextStoreSlot,
}
fn ttl() -> u64 {
	900
}
fn capacity() -> usize {
	1024
}
impl CrossComponentConfig {
	pub fn egress_classification(&self, context: DataClassification) -> DataClassification {
		if self.restrict_untrusted_payloads {
			DataClassification::Restricted
		} else {
			context
		}
	}

	pub fn validate(&self) -> Result<(), String> {
		if let Some(sqlite) = &self.sqlite {
			sqlite.validate()?;
			if self.storage.is_some()
				|| sqlite.namespace != self.namespace
				|| sqlite.max_contexts != self.max_contexts
			{
				return Err(
					"crossComponent.sqlite requires matching namespace/maxContexts and excludes storage"
						.into(),
				);
			}
			#[cfg(not(feature = "rag-sqlite"))]
			return Err("crossComponent.sqlite requires the security-rag-sqlite build feature".into());
		}
		if let Some(storage) = &self.storage {
			storage.validate()?;
		}
		if self.namespace.is_empty()
			|| self.namespace.trim() != self.namespace
			|| self.namespace.len() > 128
			|| !(1..=86400).contains(&self.ttl_seconds)
			|| !(1..=16384).contains(&self.max_contexts)
		{
			return Err("crossComponent requires a namespace and bounded lifetime/capacity".into());
		}
		for class in [
			DataClassification::Public,
			DataClassification::Internal,
			DataClassification::Restricted,
		] {
			if self
				.destinations
				.iter()
				.filter(|p| p.classification == class)
				.count()
				!= 1
			{
				return Err(
					"crossComponent.destinations requires exactly one policy for each classification".into(),
				);
			}
		}
		if self.destinations.len() != 3 {
			return Err("invalid crossComponent.destinations".into());
		}
		for policy in &self.destinations {
			policy.validate()?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	fn sqlite() -> CrossComponentConfig {
		serde_json::from_value(serde_json::json!({"namespace":"docs", "maxContexts":16,
			"destinations":[{"classification":"public"},{"classification":"internal"},{"classification":"restricted"}],
			"sqlite":{"path":"/tmp/asp-test.sqlite","namespace":"docs","maxContexts":16,"maxDocuments":16,
				"maxDatabaseBytes":1048576,"busyTimeoutMillis":100}
		})).unwrap()
	}
	#[test]
	fn sqlite_declarations_must_match_context_limits_and_exclude_journals() {
		let mut config = sqlite();
		config.sqlite.as_mut().unwrap().namespace.push_str("-other");
		assert!(
			config
				.validate()
				.unwrap_err()
				.contains("matching namespace")
		);
		let mut config = sqlite();
		config.max_contexts += 1;
		assert!(
			config
				.validate()
				.unwrap_err()
				.contains("matching namespace")
		);
		let mut config = sqlite();
		config.storage = Some(security_audit::StateJournalConfig {
			path: "/tmp/contexts.jsonl".into(),
			max_bytes: 1048576,
		});
		assert!(config.validate().unwrap_err().contains("excludes storage"));
	}
	#[test]
	fn sqlite_selection_is_explicit_and_feature_checked() {
		let config = sqlite();
		#[cfg(feature = "rag-sqlite")]
		config.validate().unwrap();
		#[cfg(not(feature = "rag-sqlite"))]
		assert!(
			config
				.validate()
				.unwrap_err()
				.contains("security-rag-sqlite")
		);
		let encoded = serde_json::to_value(&config).unwrap();
		assert!(encoded.get("store").is_none());
		assert_eq!(encoded["sqlite"]["maxContexts"], 16);
		assert!(
			config.context_store().is_err(),
			"persistent declarations never fall back before initialization"
		);
	}

	#[test]
	fn restricted_egress_is_opt_in_and_legacy_serialization_is_stable() {
		let legacy = sqlite();
		let wire = serde_json::to_value(&legacy).unwrap();
		assert!(wire.get("restrictUntrustedPayloads").is_none());
		assert_eq!(
			legacy.egress_classification(DataClassification::Public),
			DataClassification::Public
		);
		let mut explicit = wire.clone();
		explicit["restrictUntrustedPayloads"] = serde_json::json!(false);
		let explicit: CrossComponentConfig = serde_json::from_value(explicit).unwrap();
		assert_eq!(serde_json::to_value(explicit).unwrap(), wire);

		let mut strict = legacy;
		strict.restrict_untrusted_payloads = true;
		assert_ne!(serde_json::to_value(&strict).unwrap(), wire);
		for class in [
			DataClassification::Public,
			DataClassification::Internal,
			DataClassification::Restricted,
		] {
			assert_eq!(
				strict.egress_classification(class),
				DataClassification::Restricted
			);
		}
	}
}
