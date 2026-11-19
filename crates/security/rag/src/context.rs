//! Context assembly guard for already-authorized RAG chunks.

use std::sync::Mutex;

use chrono::{DateTime, Utc};
use security_audit::AuditSink;
use security_pipeline::{
	Authorizer, GatewayError, GatewayIdentity, SecurityPipeline, context_assemble_for_identity,
};
use security_types::Subject;
use serde::{Deserialize, Serialize};

use crate::{AuthorizedContext, DataClassification, KnowledgeChunk};

const DEFAULT_INDIRECT_INSTRUCTIONS: [&str; 6] = [
	"ignore previous instructions",
	"ignore all previous instructions",
	"disregard previous instructions",
	"system message",
	"developer message",
	"do not follow the previous",
];

/// Whether an indirect-injection finding removes a Chunk or is reported while preserving content.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum ContextGuardMode {
	/// Remove a Chunk that contains a configured indirect-instruction pattern.
	#[default]
	Enforce,
	/// Preserve the Chunk while producing a finding, for staged deployments.
	Shadow,
}

/// Selects the built-in indirect-instruction signals when no custom patterns are configured.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum ContextGuardRuleSet {
	#[default]
	Legacy,
	Contextual,
}

impl ContextGuardRuleSet {
	fn is_legacy(&self) -> bool {
		*self == Self::Legacy
	}
}

/// Context-level controls are intentionally separate from retrieval ACLs: content may be allowed
/// to read but still unsafe to present as model instructions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ContextGuardConfig {
	#[serde(default)]
	pub mode: ContextGuardMode,
	#[serde(default, skip_serializing_if = "ContextGuardRuleSet::is_legacy")]
	pub rule_set: ContextGuardRuleSet,
	/// A supplied list replaces the built-in rules with case-insensitive literal matching.
	#[serde(
		default,
		deserialize_with = "deserialize_instruction_patterns",
		skip_serializing_if = "Option::is_none"
	)]
	pub indirect_instruction_patterns: Option<Vec<String>>,
	/// Chunks with these labels retain their provenance but have content replaced before assembly.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub redact_labels: Vec<String>,
}

fn deserialize_instruction_patterns<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
	Vec::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ContextFindingKind {
	IndirectPromptInjection,
	SensitiveLabelRedacted,
}

/// A finding intentionally identifies a rule instead of reproducing untrusted Chunk text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContextFinding {
	pub chunk_id: String,
	pub kind: ContextFindingKind,
	pub rule_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedContext {
	pub corpus_id: String,
	pub query_hash: String,
	pub chunks: Vec<KnowledgeChunk>,
	pub context_tokens: u64,
	/// Highest class among chunks that remain after enforcement/redaction. Redaction does not
	/// downgrade a chunk; a future downgrade requires a separately audited declassification step.
	pub classification: Option<DataClassification>,
	pub removed_chunk_ids: Vec<String>,
	pub redacted_chunk_ids: Vec<String>,
	pub findings: Vec<ContextFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextAuditOutcome {
	Allowed,
	Modified,
	Denied,
}

/// Context-specific audit payload. It never includes query text or Chunk content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextAuditEvent {
	pub request_id: String,
	pub subject: Subject,
	pub corpus_id: String,
	pub query_hash: String,
	pub outcome: ContextAuditOutcome,
	pub accepted_chunk_ids: Vec<String>,
	pub classification: Option<DataClassification>,
	pub removed_chunk_ids: Vec<String>,
	pub redacted_chunk_ids: Vec<String>,
	pub findings: Vec<ContextFinding>,
	pub reason: Option<String>,
	pub timestamp: DateTime<Utc>,
}

pub trait ContextAuditSink: Send + Sync {
	fn record(&self, event: ContextAuditEvent);
}

impl<T: ContextAuditSink + ?Sized> ContextAuditSink for &T {
	fn record(&self, event: ContextAuditEvent) {
		(*self).record(event);
	}
}

#[derive(Default)]
pub struct InMemoryContextAuditSink {
	events: Mutex<Vec<ContextAuditEvent>>,
}

impl InMemoryContextAuditSink {
	pub fn events(&self) -> Vec<ContextAuditEvent> {
		self
			.events
			.lock()
			.expect("context audit sink lock poisoned")
			.clone()
	}
}

impl ContextAuditSink for InMemoryContextAuditSink {
	fn record(&self, event: ContextAuditEvent) {
		self
			.events
			.lock()
			.expect("context audit sink lock poisoned")
			.push(event);
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextAssemblyError {
	InvalidConfig(String),
	GatewayDenied(GatewayError),
}

/// A deterministic, configurable guard for context that has already passed retrieval ACL checks.
pub struct ContextGuard {
	mode: ContextGuardMode,
	instructions: InstructionRules,
	redact_labels: Vec<String>,
}

enum InstructionRules {
	Literal(Vec<String>),
	Contextual,
}

impl ContextGuard {
	pub fn new(config: ContextGuardConfig) -> Result<Self, ContextAssemblyError> {
		let instructions = match config.indirect_instruction_patterns {
			Some(patterns) => {
				if patterns.iter().any(|pattern| pattern.trim().is_empty()) {
					return Err(ContextAssemblyError::InvalidConfig(
						"indirectInstructionPatterns must not contain empty values".into(),
					));
				}
				InstructionRules::Literal(
					patterns
						.iter()
						.map(|pattern| pattern.to_lowercase())
						.collect(),
				)
			},
			None if config.rule_set == ContextGuardRuleSet::Contextual => InstructionRules::Contextual,
			None => InstructionRules::Literal(DEFAULT_INDIRECT_INSTRUCTIONS.map(str::to_owned).into()),
		};
		Ok(Self {
			mode: config.mode,
			instructions,
			redact_labels: config.redact_labels,
		})
	}

	/// Authorizes the `ContextAssemble` action, then applies injection isolation and label redaction.
	pub fn assemble<A, S, CS>(
		&self,
		pipeline: &SecurityPipeline<A, S>,
		audit: &CS,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		context: AuthorizedContext,
	) -> Result<GuardedContext, ContextAssemblyError>
	where
		A: Authorizer,
		S: AuditSink,
		CS: ContextAuditSink,
	{
		let (action, arguments) = Self::assembly_action(request_id.into(), identity, &context);
		let decision = pipeline.authorize(&action, Some(&arguments));
		self.finish_assembly(audit, action, context, decision)
	}

	pub async fn assemble_async<A, S, CS>(
		&self,
		pipeline: &SecurityPipeline<A, S>,
		audit: &CS,
		request_id: impl Into<String>,
		identity: GatewayIdentity,
		context: AuthorizedContext,
	) -> Result<GuardedContext, ContextAssemblyError>
	where
		A: Authorizer,
		S: AuditSink,
		CS: ContextAuditSink,
	{
		let (action, arguments) = Self::assembly_action(request_id.into(), identity, &context);
		let decision = pipeline.authorize_async(&action, Some(&arguments)).await;
		self.finish_assembly(audit, action, context, decision)
	}

	fn assembly_action(
		request_id: String,
		identity: GatewayIdentity,
		context: &AuthorizedContext,
	) -> (security_types::ActionRequest, serde_json::Value) {
		let action = context_assemble_for_identity(request_id, identity, context.corpus_id.clone());
		let arguments = serde_json::json!({
			"queryHash": context.query_hash,
			"chunkIds": context.chunks.iter().map(|chunk| chunk.id.clone()).collect::<Vec<_>>(),
			"contextTokens": context.context_tokens,
		});
		(action, arguments)
	}

	fn finish_assembly<CS: ContextAuditSink>(
		&self,
		audit: &CS,
		action: security_types::ActionRequest,
		context: AuthorizedContext,
		decision: Result<security_types::Decision, GatewayError>,
	) -> Result<GuardedContext, ContextAssemblyError> {
		if let Err(error) = decision {
			audit.record(ContextAuditEvent {
				request_id: action.request_id,
				subject: action.subject,
				corpus_id: action.resource.id,
				query_hash: context.query_hash,
				outcome: ContextAuditOutcome::Denied,
				accepted_chunk_ids: Vec::new(),
				classification: None,
				removed_chunk_ids: Vec::new(),
				redacted_chunk_ids: Vec::new(),
				findings: Vec::new(),
				reason: Some(format!("{error:?}")),
				timestamp: Utc::now(),
			});
			return Err(ContextAssemblyError::GatewayDenied(error));
		}

		let guarded = self.inspect(context);
		let outcome = if guarded.findings.is_empty() {
			ContextAuditOutcome::Allowed
		} else {
			ContextAuditOutcome::Modified
		};
		audit.record(ContextAuditEvent {
			request_id: action.request_id,
			subject: action.subject,
			corpus_id: guarded.corpus_id.clone(),
			query_hash: guarded.query_hash.clone(),
			outcome,
			accepted_chunk_ids: guarded
				.chunks
				.iter()
				.map(|chunk| chunk.id.clone())
				.collect(),
			classification: guarded.classification,
			removed_chunk_ids: guarded.removed_chunk_ids.clone(),
			redacted_chunk_ids: guarded.redacted_chunk_ids.clone(),
			findings: guarded.findings.clone(),
			reason: None,
			timestamp: Utc::now(),
		});
		Ok(guarded)
	}

	pub fn inspect(&self, context: AuthorizedContext) -> GuardedContext {
		let mut chunks = Vec::new();
		let mut context_tokens = 0;
		let mut removed_chunk_ids = Vec::new();
		let mut redacted_chunk_ids = Vec::new();
		let mut findings = Vec::new();

		for mut chunk in context.chunks {
			if let Some(rule_id) = self.indirect_instruction_rule(&chunk.content) {
				findings.push(ContextFinding {
					chunk_id: chunk.id.clone(),
					kind: ContextFindingKind::IndirectPromptInjection,
					rule_id,
				});
				if self.mode == ContextGuardMode::Enforce {
					removed_chunk_ids.push(chunk.id);
					continue;
				}
			}
			if self.has_redacted_label(&chunk) {
				findings.push(ContextFinding {
					chunk_id: chunk.id.clone(),
					kind: ContextFindingKind::SensitiveLabelRedacted,
					rule_id: "security-label".into(),
				});
				chunk.content = "[REDACTED BY RAG CONTEXT POLICY]".into();
				redacted_chunk_ids.push(chunk.id.clone());
			}
			context_tokens += chunk.token_count;
			chunks.push(chunk);
		}

		let classification = chunks.iter().map(|chunk| chunk.classification).max();
		GuardedContext {
			corpus_id: context.corpus_id,
			query_hash: context.query_hash,
			chunks,
			context_tokens,
			classification,
			removed_chunk_ids,
			redacted_chunk_ids,
			findings,
		}
	}

	fn indirect_instruction_rule(&self, content: &str) -> Option<String> {
		let matched = match &self.instructions {
			InstructionRules::Literal(patterns) if patterns.is_empty() => None,
			InstructionRules::Literal(patterns) => {
				let normalized = content.to_lowercase();
				patterns
					.iter()
					.position(|pattern| normalized.contains(pattern))
			},
			InstructionRules::Contextual => {
				let normalized = normalized_instruction_view(content);
				DEFAULT_INDIRECT_INSTRUCTIONS.iter().position(|pattern| {
					if matches!(*pattern, "system message" | "developer message") {
						role_command(&normalized, pattern)
					} else {
						normalized.contains(pattern)
					}
				})
			},
		};
		matched.map(|index| format!("indirect-instruction-{index}"))
	}

	fn has_redacted_label(&self, chunk: &KnowledgeChunk) -> bool {
		chunk.labels.iter().any(|label| {
			self
				.redact_labels
				.iter()
				.any(|redacted| label.eq_ignore_ascii_case(redacted))
		})
	}
}

/// Transform a single already bounded Chunk only for matching. Keep the originals for assembly.
fn normalized_instruction_view(content: &str) -> String {
	let mut view = String::with_capacity(content.len());
	let mut space = false;
	for ch in content.chars() {
		if matches!(ch, '\u{00ad}' | '\u{200b}' | '\u{2060}' | '\u{feff}') {
			continue;
		}
		if ch.is_whitespace() {
			space = !view.is_empty();
		} else {
			if space {
				view.push(' ');
				space = false;
			}
			view.extend(ch.to_lowercase());
		}
	}
	view
}

fn role_command(text: &str, role: &str) -> bool {
	const SEPARATORS: [char; 7] = [' ', ':', ']', '>', '\'', '"', '`'];
	text.match_indices(role).any(|(start, role)| {
		if text[..start].ends_with(|ch: char| ch.is_alphanumeric() || ch == '_') {
			return false;
		}
		let tail = &text[start + role.len()..];
		let Some(command) = tail.strip_prefix(SEPARATORS) else {
			return false;
		};
		matches!(
			command
				.trim_start_matches(SEPARATORS)
				.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
				.next(),
			Some(
				"call"
					| "invoke"
					| "execute"
					| "run"
					| "ignore"
					| "disregard"
					| "override"
					| "obey"
					| "reveal"
					| "send"
			)
		)
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn explicit_patterns_keep_their_literal_behavior() {
		let config = serde_json::from_value(serde_json::json!({
			"ruleSet": "contextual", "indirectInstructionPatterns": ["system message"]
		}))
		.unwrap();
		let guard = ContextGuard::new(config).unwrap();
		assert!(
			guard
				.indirect_instruction_rule("The SYSTEM MESSAGE field")
				.is_some()
		);
		assert!(guard.indirect_instruction_rule("system\nmessage").is_none());
		assert!(
			guard
				.indirect_instruction_rule("ignore previous instructions")
				.is_none()
		);
		let config = serde_json::from_value(serde_json::json!({
			"ruleSet": "contextual", "indirectInstructionPatterns": []
		}))
		.unwrap();
		let guard = ContextGuard::new(config).unwrap();
		assert!(
			guard
				.indirect_instruction_rule("ignore previous instructions")
				.is_none()
		);
		for invalid in ["null", r#"[" \t"]"#] {
			let wire = format!("{{\"indirectInstructionPatterns\":{invalid}}}");
			assert!(
				serde_json::from_str::<ContextGuardConfig>(&wire)
					.ok()
					.and_then(|config| ContextGuard::new(config).ok())
					.is_none()
			);
		}
	}

	#[test]
	fn normalized_matches_preserve_shadow_text_and_provenance() {
		let chunk: KnowledgeChunk = serde_json::from_value(serde_json::json!({
			"id":"chunk", "documentId":"doc", "corpusId":"docs", "tenantId":"tenant-a",
			"content":"DISREGARD\u{2060}\u{00a0}previous\n instructions.", "sourceHash":"hash", "tokenCount":5,
			"classification":"restricted", "classificationSource":"fixture"
		}))
		.unwrap();
		let context = AuthorizedContext {
			corpus_id: "docs".into(),
			query_hash: "query-hash".into(),
			chunks: vec![chunk.clone()],
			context_tokens: 5,
			rejected: vec![],
		};
		let mut config = ContextGuardConfig {
			mode: ContextGuardMode::Shadow,
			rule_set: ContextGuardRuleSet::Contextual,
			..Default::default()
		};
		let shadow = ContextGuard::new(config.clone())
			.unwrap()
			.inspect(context.clone());
		assert_eq!(shadow.chunks, [chunk]);
		assert_eq!(shadow.context_tokens, 5);
		assert_eq!(shadow.classification, Some(DataClassification::Restricted));
		assert_eq!(shadow.findings[0].rule_id, "indirect-instruction-2");
		config.mode = ContextGuardMode::Enforce;
		let enforced = ContextGuard::new(config).unwrap().inspect(context);
		assert_eq!(enforced.removed_chunk_ids, ["chunk"]);
		assert!(enforced.chunks.is_empty());
		assert_eq!(enforced.context_tokens, 0);
		assert_eq!(enforced.findings, shadow.findings);
	}
}
