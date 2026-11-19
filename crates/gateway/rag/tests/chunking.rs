use gateway_rag::{DocumentChunker, FixedWindowChunker};
use security_rag::{DataClassification, IndexedDocument, SourceOrigin, TrustedChunkAccess};

// Preserve the previous splitter as a migration oracle, including whitespace and character IDs.
fn previous_chunks(content: &str, width: usize) -> Vec<(usize, String)> {
	let chars: Vec<_> = content.chars().collect();
	let mut result = Vec::new();
	let mut start = 0;
	while start < chars.len() {
		let mut end = start.saturating_add(width).min(chars.len());
		if end < chars.len()
			&& let Some(offset) = chars[start..end]
				.iter()
				.rposition(|c| c.is_whitespace())
				.filter(|i| *i > 0)
		{
			end = start + offset;
		}
		result.push((start, chars[start..end].iter().collect()));
		start = end;
	}
	result
}

#[test]
fn utf8_windows_preserve_legacy_content_ids_and_security_metadata() {
	let access = TrustedChunkAccess {
		allowed_users: vec!["alice".into()],
		allowed_agents: vec!["assistant".into()],
		..Default::default()
	};
	let repeated = "a b 甲😀\n".repeat(50);
	for content in [
		"a",
		" longwordwithoutbreaks",
		"a  b\tc\n end ",
		"甲😀乙\u{2003}丙 丁",
		repeated.as_str(),
	] {
		for width in (1..=16).chain([usize::MAX]) {
			for lifecycle in [false, true] {
				let document = IndexedDocument {
					tenant_id: "tenant".into(),
					corpus_id: "corpus".into(),
					document_id: "document".into(),
					source_uri: "https://source.test/document".into(),
					source_hash: "a".repeat(64),
					source_origin: if lifecycle {
						SourceOrigin::Lifecycle {
							authority: "authority".into(),
							version: 7,
							revision: 9,
							origin: Box::new(SourceOrigin::Submitted),
						}
					} else {
						SourceOrigin::Submitted
					},
					content: content.into(),
					labels: vec!["private".into()],
					classification: DataClassification::Restricted,
					classification_source: "trusted-rule".into(),
				};
				let actual = FixedWindowChunker::new(width)
					.unwrap()
					.split(&document, &access)
					.unwrap();
				assert_eq!(
					actual
						.iter()
						.map(|c| c.content.as_str())
						.collect::<String>(),
					content
				);
				let expected: Vec<_> = previous_chunks(content, width)
					.into_iter()
					.map(|(start, text)| {
						let tokens = (text.split_whitespace().count() as u64).max(1);
						document.to_chunk(format!("document:{start}"), text, tokens, access.clone())
					})
					.collect();
				assert_eq!(
					serde_json::to_value(actual).unwrap(),
					serde_json::to_value(expected).unwrap(),
					"width={width}, lifecycle={lifecycle}"
				);
			}
		}
	}
}
