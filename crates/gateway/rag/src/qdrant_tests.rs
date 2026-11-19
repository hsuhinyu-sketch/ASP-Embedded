use super::*;
use axum::{
	Router,
	body::Bytes,
	extract::State,
	http::{HeaderMap, Method, StatusCode, Uri},
	routing::any,
};
use std::sync::{
	Mutex,
	atomic::{AtomicUsize, Ordering},
};

struct Captured {
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	body: Vec<u8>,
}
struct Sink {
	endpoint: String,
	calls: Arc<Mutex<Vec<Captured>>>,
	task: tokio::task::JoinHandle<()>,
}
impl Sink {
	async fn start(status: StatusCode) -> Self {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let endpoint = format!("http://{}", listener.local_addr().unwrap());
		let calls = Arc::new(Mutex::new(Vec::new()));
		let app = Router::new()
			.fallback(any(
				move |State(calls): State<Arc<Mutex<Vec<Captured>>>>,
				      method: Method,
				      uri: Uri,
				      headers: HeaderMap,
				      body: Bytes| async move {
					calls.lock().unwrap().push(Captured {
						method,
						uri,
						headers,
						body: body.to_vec(),
					});
					(status, "{}")
				},
			))
			.with_state(calls.clone());
		let task = tokio::spawn(async move {
			axum::serve(listener, app).await.unwrap();
		});
		Self {
			endpoint,
			calls,
			task,
		}
	}
}
impl Drop for Sink {
	fn drop(&mut self) {
		self.task.abort();
	}
}

struct Embeddings {
	values: Vec<f32>,
	calls: AtomicUsize,
	fail_at: Option<usize>,
	empty_at: Option<usize>,
	pending_at: Option<usize>,
	entered: Arc<tokio::sync::Notify>,
}
impl Embeddings {
	fn new(values: Vec<f32>) -> Self {
		Self {
			values,
			calls: AtomicUsize::new(0),
			fail_at: None,
			empty_at: None,
			pending_at: None,
			entered: Default::default(),
		}
	}
}
#[async_trait::async_trait]
impl EmbeddingProvider for Embeddings {
	async fn embed(&self, _: &str) -> Result<Vec<f32>, String> {
		let index = self.calls.fetch_add(1, Ordering::SeqCst);
		if self.pending_at == Some(index) {
			self.entered.notify_one();
			std::future::pending::<()>().await;
		}
		if self.fail_at == Some(index) {
			return Err("embedding fixture failure".into());
		}
		Ok(if self.empty_at == Some(index) {
			Vec::new()
		} else {
			self.values.clone()
		})
	}
}
fn key() -> IntegrityKey {
	IntegrityKey::from_hex("test-key", &"11".repeat(32)).unwrap()
}
fn chunks(count: usize) -> Vec<KnowledgeChunk> {
	let doc = IndexedDocument {
		tenant_id: "tenant-a".into(),
		corpus_id: "corpus".into(),
		document_id: "文档\"id".into(),
		content: "text".into(),
		source_uri: "https://source.test/doc".into(),
		source_hash: "a".repeat(64),
		source_origin: security_rag::SourceOrigin::Submitted,
		labels: vec!["private".into()],
		classification: security_rag::DataClassification::Restricted,
		classification_source: "trusted-rule".into(),
	};
	(0..count)
		.map(|i| {
			doc.to_chunk(
				format!("chunk-{i}"),
				format!("中文😀 \"text\" \\ newline\n{i}"),
				7,
				TrustedChunkAccess {
					allowed_users: vec!["alice".into()],
					allowed_agents: vec!["assistant".into()],
					allow_tenant_authenticated: false,
					expires_at: Some(
						DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
							.unwrap()
							.with_timezone(&Utc),
					),
				},
			)
		})
		.collect()
}
fn backend(
	sink: &Sink,
	embeddings: Embeddings,
	named: bool,
	signed: bool,
) -> QdrantBackend<Embeddings, FixedWindowChunker> {
	let mut b = QdrantBackend::new(
		Client::builder()
			.no_proxy()
			.timeout(std::time::Duration::from_secs(5))
			.build()
			.unwrap(),
		QdrantBackendConfig {
			endpoint: sink.endpoint.clone(),
			collection: "docs".into(),
			quarantine_collection: "quarantine".into(),
			api_key: Some("fixture-api-key".into()),
			vector_name: named.then(|| "向量\"name".into()),
			default_chunk_access: Default::default(),
			integrity: None,
		},
		embeddings,
		FixedWindowChunker::new(512).unwrap(),
	)
	.unwrap();
	if signed {
		b.integrity = Some(key());
	}
	b
}
// Preserve the previous aggregate encoder as the wire-format migration oracle.
fn previous_body(
	chunks: &[KnowledgeChunk],
	vector: &[f32],
	name: Option<&str>,
	rules: &[String],
	key: Option<&IntegrityKey>,
) -> Vec<u8> {
	let points: Vec<_> = chunks
		.iter()
		.map(|chunk| {
			let mut payload = qdrant_payload(chunk, rules);
			if let Some(key) = key {
				payload["integrity"] =
					serde_json::to_value(key.sign_json("rag-qdrant-chunk", &payload).unwrap()).unwrap();
			}
			json!({"id":chunk.id,"vector":qdrant_vector(vector.to_vec(),name),"payload":payload})
		})
		.collect();
	serde_json::to_vec(&json!({"points":points})).unwrap()
}

#[tokio::test]
async fn pointwise_encoding_preserves_wire_bytes_metadata_and_proofs() {
	let values = vec![
		0.1,
		-0.0,
		f32::MAX,
		f32::MIN,
		f32::MIN_POSITIVE,
		f32::from_bits(1),
		f32::INFINITY,
		f32::NEG_INFINITY,
		f32::NAN,
	];
	for named in [false, true] {
		for signed in [false, true] {
			for count in [0, 1, 3] {
				let sink = Sink::start(StatusCode::OK).await;
				let backend = backend(&sink, Embeddings::new(values.clone()), named, signed);
				let chunks = chunks(count);
				let rules = vec!["quarantine-rule".into(), "规则\"id".into()];
				let expected = previous_body(
					&chunks,
					&values,
					backend.config.vector_name.as_deref(),
					&rules,
					backend.integrity.as_ref(),
				);
				backend
					.upsert("quarantine", chunks.clone(), rules.clone())
					.await
					.unwrap();
				let calls = sink.calls.lock().unwrap();
				assert_eq!(calls.len(), 1);
				let call = &calls[0];
				assert_eq!(call.method, Method::PUT);
				assert_eq!(call.uri, "/collections/quarantine/points?wait=true");
				assert_eq!(call.headers["api-key"], "fixture-api-key");
				assert_eq!(call.headers["content-type"], "application/json");
				assert_eq!(
					call.body, expected,
					"named={named},signed={signed},count={count}"
				);
				let body: Value = serde_json::from_slice(&call.body).unwrap();
				for (point, chunk) in body["points"].as_array().unwrap().iter().zip(&chunks) {
					assert_eq!(
						verified_chunk_from_payload(
							point["id"].clone(),
							point["payload"].clone(),
							backend.integrity.as_ref()
						)
						.unwrap(),
						*chunk
					);
					assert_eq!(point["payload"]["quarantineRuleIds"], json!(rules));
				}
			}
		}
	}
}

#[tokio::test]
async fn preparation_failures_never_send_partial_points_and_http_failure_is_not_retried() {
	for empty in [false, true] {
		let sink = Sink::start(StatusCode::OK).await;
		let mut embeddings = Embeddings::new(vec![0.1, 0.2]);
		if empty {
			embeddings.empty_at = Some(1);
		} else {
			embeddings.fail_at = Some(1);
		}
		let backend = backend(&sink, embeddings, false, true);
		let error = backend
			.upsert("docs", chunks(3), Vec::new())
			.await
			.unwrap_err();
		assert_eq!(
			error,
			if empty {
				"embedding provider returned an empty vector"
			} else {
				"embedding fixture failure"
			}
		);
		assert!(sink.calls.lock().unwrap().is_empty());
	}
	let sink = Sink::start(StatusCode::INTERNAL_SERVER_ERROR).await;
	let backend = backend(&sink, Embeddings::new(vec![0.1]), false, false);
	assert!(
		backend
			.upsert("docs", chunks(3), Vec::new())
			.await
			.unwrap_err()
			.contains("HTTP 500")
	);
	assert_eq!(sink.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn cancellation_during_later_embedding_sends_no_partial_request() {
	let sink = Sink::start(StatusCode::OK).await;
	let mut embeddings = Embeddings::new(vec![0.1]);
	embeddings.pending_at = Some(1);
	let entered = embeddings.entered.clone();
	let backend = backend(&sink, embeddings, true, true);
	let task = tokio::spawn(async move { backend.upsert("docs", chunks(3), Vec::new()).await });
	tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
		.await
		.unwrap();
	assert!(sink.calls.lock().unwrap().is_empty());
	task.abort();
	assert!(task.await.unwrap_err().is_cancelled());
	assert!(sink.calls.lock().unwrap().is_empty());
}
