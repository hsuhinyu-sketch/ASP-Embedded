use super::*;
use crate::llm::{
	LLMRequest,
	types::{SimpleChatCompletionMessage, completions},
};
use platform_core::prelude::Strng;

struct CountedRequest {
	inner: completions::Request,
	writes: usize,
}
impl RequestType for CountedRequest {
	fn pii_body(&self) -> Result<Value, AIError> {
		self.inner.pii_body()
	}
	fn replace_pii_body(&mut self, body: Value) -> Result<(), AIError> {
		self.writes += 1;
		self.inner.replace_pii_body(body)
	}
	fn model(&mut self) -> &mut Option<String> {
		self.inner.model()
	}
	fn prepend_prompts(&mut self, messages: Vec<SimpleChatCompletionMessage>) {
		self.inner.prepend_prompts(messages);
	}
	fn append_prompts(&mut self, messages: Vec<SimpleChatCompletionMessage>) {
		self.inner.append_prompts(messages);
	}
	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		self.inner.get_messages()
	}
	fn set_messages(&mut self, messages: Vec<SimpleChatCompletionMessage>) {
		self.inner.set_messages(messages);
	}
	fn to_llm_request(&self, provider: Strng, tokenize: bool) -> Result<LLMRequest, AIError> {
		self.inner.to_llm_request(provider, tokenize)
	}
}

#[tokio::test]
async fn writeback_requires_an_actual_enforced_mutation() {
	for (mode, action, text, writes, blocked) in [
		("enforce", "mask", "ordinary text", 0, false),
		("enforce", "mask", "alice@example.com", 1, false),
		("enforce", "detectOnly", "alice@example.com", 0, false),
		("enforce", "block", "alice@example.com", 0, true),
		("audit", "mask", "alice@example.com", 0, false),
		("shadow", "mask", "alice@example.com", 0, false),
	] {
		let config: SecurityConfig = serde_json::from_value(json!({
			"mode":"enforce", "policies":[{"id":"model", "enabled":true, "effect":"allow", "actionType":"modelInvoke"}],
			"pii":{"mode":mode,"policy":{"entities":{"EMAIL_ADDRESS":{"action":action}}}}
		})).unwrap();
		config
			.pii_runtime
			.prepare(config.pii.as_ref().unwrap())
			.await
			.unwrap();
		let mut parts = http::Request::new(()).into_parts().0;
		parts.extensions.insert(Bindings {
			configs: vec![Arc::new(config)],
			model: "local".into(),
		});
		let body = json!({"model":"local", "messages":[{"role":"user", "content":text}]});
		let mut request = CountedRequest {
			inner: serde_json::from_value(body).unwrap(),
			writes: 0,
		};
		assert_eq!(
			inspect(&mut request, InputFormat::Completions, &parts)
				.await
				.unwrap(),
			blocked
		);
		assert_eq!(
			request.writes, writes,
			"mode={mode}, action={action}, text={text}"
		);
		if writes == 0 {
			assert_eq!(
				request.inner.pii_body().unwrap()["messages"][0]["content"],
				text
			);
		}
	}
}
