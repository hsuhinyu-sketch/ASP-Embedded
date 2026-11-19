//! Opt-in session ownership and demand-driven response protection. Never a client credential.
#[path = "reverse.rs"]
pub(crate) mod reverse;
#[path = "subscriptions.rs"]
mod subscriptions;
#[path = "tasks.rs"]
pub(crate) mod tasks;

use super::{ClientError, handler::RelayInputs, mergestream::Messages, session::SessionManager};
use crate::http::{Body, Response};
use crate::proxy::ProxyError;
use futures_util::{StreamExt, TryStreamExt};
use gateway_mcp::capabilities::restrict_session_capabilities as session_capabilities;
use security_integration_runtime::{
	SecurityConfig, identity_binding::VerifiedOwner, mcp_sessions::McpSessionConfig,
};
use security_pipeline::GatewayIdentity;
use security_types::{ActionRequest, Decision, DecisionEffect};
use std::sync::{
	Arc, Mutex,
	atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
pub(crate) use subscriptions::prepare_subscription;

#[cfg(test)]
#[path = "session_security_tests.rs"]
mod tests;

#[derive(Clone)]
pub(crate) struct SessionScope(pub String);

#[derive(Debug)]
pub(crate) struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::AcqRel);
	}
}
pub(crate) fn reserve(counter: &Arc<AtomicUsize>, max: usize) -> Option<Arc<Slot>> {
	counter
		.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
			(n < max).then(|| n + 1)
		})
		.ok()?;
	Some(Arc::new(Slot(counter.clone())))
}

#[derive(Debug)]
pub(crate) struct SessionBinding {
	owner: VerifiedOwner,
	scope: String,
	created: Instant,
	last_access: Mutex<Instant>,
	idle_ttl: Duration,
	max_age: Duration,
	revision: gateway_contracts::ConfigLease,
	pub closed: AtomicBool,
	_slot: Arc<Slot>,
	subscriptions: Mutex<std::collections::HashMap<(String, String), subscriptions::State>>,
	reverse: Mutex<reverse::Registry>,
	tasks: Mutex<tasks::Registry>,
	flow: Option<crate::security_flow::FlowAccess>,
}
impl SessionBinding {
	pub fn expired(&self) -> bool {
		self.closed.load(Ordering::Acquire)
			|| !self.revision.is_current()
			|| self.created.elapsed() >= self.max_age
			|| self
				.last_access
				.lock()
				.map_or(true, |last| last.elapsed() >= self.idle_ttl)
	}
}

#[derive(Clone)]
pub(crate) struct SessionAccess {
	config: Arc<SecurityConfig>,
	pub limits: McpSessionConfig,
	owner: VerifiedOwner,
	identity: GatewayIdentity,
	scope: String,
	expires: i64,
	revision: gateway_contracts::ConfigLease,
	action: ActionRequest,
	pub binding: Option<Arc<SessionBinding>>,
	_stream: Arc<Slot>,
	flow: Option<crate::security_flow::FlowAccess>,
	policies: super::rbac::McpAuthorizationSet,
	legacy: Option<crate::types::agent::LegacySecurityPipeline>,
	authorization_request: Arc<http::Request<()>>,
}

pub(crate) fn digest(value: &str) -> String {
	crate::security::digest(value)
}

pub(crate) fn restrict_for_context(
	capabilities: &mut rmcp::model::ServerCapabilities,
	ctx: &super::upstream::IncomingRequestContext,
) {
	if let Some(access) = ctx.as_request().extensions().get::<SessionAccess>() {
		access.restrict_advertised_capabilities(capabilities);
	}
}

impl SessionAccess {
	fn restrict_advertised_capabilities(&self, capabilities: &mut rmcp::model::ServerCapabilities) {
		session_capabilities(capabilities, self.binding.is_some());
		if self
			.flow
			.as_ref()
			.is_some_and(crate::security_flow::FlowAccess::restricts_untrusted_payloads)
		{
			capabilities.resources = None;
			capabilities.prompts = None;
		}
		tasks::capabilities(self, capabilities);
	}

	fn security(&self) -> super::security::McpSecurity<'_> {
		super::security::McpSecurity::new(Some(&self.config), self.legacy.as_ref())
	}

	pub async fn prepare(
		parts: &mut http::request::Parts,
		inputs: &RelayInputs,
		manager: &SessionManager,
		operation: &str,
		session: Option<&str>,
	) -> Result<Option<Box<Self>>, ProxyError> {
		let Some(config) = inputs
			.security_audit
			.as_ref()
			.filter(|c| c.mcp_sessions.is_some())
		else {
			return Ok(None);
		};
		let identity = crate::security::identity_from_extensions(&parts.extensions);
		let scope = parts
			.extensions
			.get::<SessionScope>()
			.map(|s| s.0.clone())
			.unwrap_or_default();
		let resource = session.map_or_else(
			|| scope.clone(),
			|s| serde_json::to_string(&(&scope, digest(s))).expect("strings serialize"),
		);
		let action = security_pipeline::mcp_session_for_identity(
			crate::security::request_id(&mut parts.extensions),
			identity.clone(),
			operation,
			resource,
		);
		let refuse = |rule| deny(&action, rule);
		config
			.validate_composition()
			.map_err(|_| refuse("configuration"))?;
		if scope.is_empty() {
			return Err(refuse("scope"));
		}
		if inputs
			.backend
			.targets
			.iter()
			.any(|t| !matches!(t.spec, crate::types::agent::McpTargetSpec::Mcp(_)))
		{
			return Err(refuse("unsupported-upstream-transport"));
		}
		let claims = parts
			.extensions
			.get::<crate::http::jwt::Claims>()
			.ok_or_else(|| refuse("identity"))?;
		let issuer = claims
			.inner
			.get("iss")
			.and_then(|v| v.as_str())
			.ok_or_else(|| refuse("identity"))?;
		let owner = VerifiedOwner::from_identity(&identity, issuer).map_err(|_| refuse("identity"))?;
		let expires = claims
			.inner
			.get("exp")
			.and_then(|v| v.as_i64())
			.ok_or_else(|| refuse("identity"))?;
		let revision = parts
			.extensions
			.get::<gateway_contracts::ConfigLease>()
			.cloned()
			.ok_or_else(|| refuse("configuration"))?;
		let limits = config.mcp_sessions.clone().expect("enabled");
		if limits.tasks.is_some() && inputs.backend.targets.len() != 1 {
			return Err(refuse("tasks-require-one-upstream"));
		}
		let slot = reserve(&manager.protected_streams, limits.max_streams)
			.ok_or_else(|| refuse("stream-limit"))?;
		let access = Self {
			config: config.clone(),
			limits,
			owner,
			identity,
			scope,
			expires,
			revision,
			action,
			binding: None,
			_stream: slot,
			flow: crate::security_flow::prepare_async(config, &parts.headers, &parts.extensions).await?,
			policies: inputs.policies.clone(),
			legacy: inputs.security_pipeline.clone(),
			authorization_request: Arc::new(http::Request::from_parts(parts.clone(), ())),
		};
		access.check().await?;
		Ok(Some(Box::new(access)))
	}
	pub(super) async fn current(&self) -> Result<(), ProxyError> {
		self.current_local()?;
		if let Some(flow) = &self.flow {
			flow.current_async().await?;
		}
		self.current_local()
	}
	pub(crate) fn current_local(&self) -> Result<(), ProxyError> {
		if self.expires <= chrono::Utc::now().timestamp() {
			return Err(self.denial("credential-expired"));
		}
		if !self.revision.is_current() {
			return Err(self.denial("config-changed"));
		}
		if let Some(binding) = &self.binding {
			self.validate_binding(binding)?;
		}
		Ok(())
	}

	pub fn check(&self) -> futures_util::future::BoxFuture<'_, Result<(), ProxyError>> {
		Box::pin(async move {
			self.current().await?;
			let security = self.security();
			Box::pin(super::dispatch::authorize(
				http_for_authorization(self),
				&self.action,
				security.authorize_async(&self.action, None),
			))
			.await?
			.map_err(|_| self.denial("authorization"))?;
			self.current().await
		})
	}

	fn validate_binding(&self, binding: &SessionBinding) -> Result<(), ProxyError> {
		if self.owner != binding.owner
			|| match (&self.flow, &binding.flow) {
				(None, None) => false,
				(Some(a), Some(b)) => !a.same_context(b),
				_ => true,
			} || self.scope != binding.scope
			|| binding.expired()
			|| binding.created.elapsed() >= Duration::from_secs(self.limits.max_session_seconds)
			|| binding
				.last_access
				.lock()
				.map_err(|_| self.denial("store-unavailable"))?
				.elapsed()
				>= binding.idle_ttl
			|| !binding.revision.is_current()
		{
			return Err(self.denial("unknown-or-not-owner"));
		}
		Ok(())
	}
	pub async fn bind(&mut self, binding: Arc<SessionBinding>) -> Result<(), ProxyError> {
		self.validate_binding(&binding)?;
		self.binding = Some(binding);
		self.check().await
	}

	/// Call only after an authorized message is accepted. Reauthorization timers are not activity.
	async fn record_activity(&self) -> Result<(), ProxyError> {
		self.current().await?;
		if let Some(binding) = &self.binding {
			let mut last = binding
				.last_access
				.lock()
				.map_err(|_| self.denial("store-unavailable"))?;
			// Do not revive a binding that expired between current() and taking the lock.
			if last.elapsed() >= binding.idle_ttl {
				return Err(self.denial("unknown-or-not-owner"));
			}
			*last = Instant::now();
		}
		Ok(())
	}
	pub fn create_binding(
		&mut self,
		manager: &SessionManager,
		ttl: Duration,
	) -> Result<(), ProxyError> {
		manager.prune_protected();
		let slot = reserve(&manager.protected_sessions, self.limits.max_sessions)
			.ok_or_else(|| self.denial("capacity"))?;
		self.binding = Some(Arc::new(SessionBinding {
			owner: self.owner.clone(),
			scope: self.scope.clone(),
			created: Instant::now(),
			last_access: Mutex::new(Instant::now()),
			idle_ttl: ttl,
			max_age: Duration::from_secs(self.limits.max_session_seconds),
			revision: self.revision.clone(),
			closed: AtomicBool::new(false),
			_slot: slot,
			subscriptions: Mutex::new(Default::default()),
			reverse: Mutex::new(Default::default()),
			tasks: Mutex::new(Default::default()),
			flow: self.flow.clone(),
		}));
		Ok(())
	}
	pub fn install(&self, parts: &mut http::request::Parts) {
		parts.extensions.insert(self.clone());
		if let Some(flow) = &self.flow {
			parts.extensions.insert(flow.clone());
		}
	}
	/// Keep polling the pending operation while periodic authorization waits for storage it may
	/// itself own. Hold one completed result until authorization finishes; never spawn a reader.
	async fn checked_wait<'a, T>(
		&'a self,
		future: impl Future<Output = T>,
		end: tokio::time::Instant,
		check: impl Fn() -> futures_util::future::BoxFuture<'a, Result<(), ProxyError>>,
	) -> Result<T, ProxyError> {
		let mut revision = self.revision.clone();
		tokio::select! {
			biased;
			_ = revision.changed() => return Err(self.denial("config-changed")),
			_ = tokio::time::sleep_until(end) => return Err(self.denial("stream-timeout")),
			result = check() => result?,
		}
		tokio::pin!(future);
		let interval = Duration::from_secs(self.limits.reauthorize_seconds);
		let mut next_check = tokio::time::Instant::now() + interval;
		let mut pending: Option<futures_util::future::BoxFuture<'_, Result<(), ProxyError>>> = None;
		let mut output = None;
		loop {
			tokio::select! {
				biased;
				_ = revision.changed() => return Err(self.denial("config-changed")),
				_ = tokio::time::sleep_until(end) => return Err(self.denial("stream-timeout")),
				result = async { pending.as_mut().expect("enabled authorization").await }, if pending.is_some() => {
					result?;
					pending = None;
					if let Some(output) = output.take() { return Ok(output); }
					next_check = tokio::time::Instant::now() + interval;
				},
				value = &mut future, if output.is_none() => {
					output = Some(value);
					if pending.is_none() { pending = Some(check()); }
				},
				_ = tokio::time::sleep_until(next_check), if pending.is_none() => { pending = Some(check()); },
			}
		}
	}
	pub async fn call(
		&self,
		future: impl Future<Output = Result<Response, ProxyError>>,
	) -> Result<Response, ProxyError> {
		let end = tokio::time::Instant::now()
			+ Duration::from_secs(
				self
					.limits
					.stream_idle_seconds
					.min(self.limits.max_stream_seconds),
			);
		let result = self.checked_wait(future, end, || self.check()).await?;
		if result.as_ref().is_ok_and(|r| r.status().is_success()) {
			self.record_activity().await?;
		}
		result
	}

	pub fn denial(&self, rule: &str) -> ProxyError {
		deny(&self.action, rule)
	}
	pub async fn protect_response(&self, mut response: Response) -> Result<Response, ProxyError> {
		self.check().await?;
		response.headers_mut().insert(
			http::header::CACHE_CONTROL,
			"private, no-store".parse().expect("constant"),
		);
		for key in ["content-length", "etag", "digest", "content-digest"] {
			response.headers_mut().remove(key);
		}
		let body = std::mem::replace(response.body_mut(), Body::empty());
		let access = self.clone();
		let end = tokio::time::Instant::now() + Duration::from_secs(self.limits.max_stream_seconds);
		let idle = tokio::time::Instant::now() + Duration::from_secs(self.limits.stream_idle_seconds);
		let stream = futures_util::stream::try_unfold(
			(access, body.into_data_stream(), idle),
			move |(access, mut body, mut idle)| async move {
				let bytes = access
					.checked_wait(body.next(), idle.min(end), || access.check())
					.await?;
				match bytes {
					None => Ok(None),
					Some(Err(_)) => Err(access.denial("response-stream")),
					Some(Ok(bytes)) => {
						idle =
							tokio::time::Instant::now() + Duration::from_secs(access.limits.stream_idle_seconds);
						Ok(Some((bytes, (access, body, idle))))
					},
				}
			},
		);
		*response.body_mut() = Body::from_stream(stream);
		Ok(response)
	}
	pub async fn verify_initialize(
		&self,
		response: Response,
		id: &rmcp::model::RequestId,
	) -> Result<Response, ProxyError> {
		let response = self.protect_response(response).await?;
		let (parts, body) = response.into_parts();
		let bytes = axum::body::to_bytes(body, self.limits.max_message_bytes)
			.await
			.map_err(|_| self.denial("initialize-response"))?;
		use tokio_util::codec::Decoder;
		let mut buffered = bytes::BytesMut::from(bytes.as_ref());
		let mut decoder =
			tokio_sse_codec::SseDecoder::<bytes::Bytes>::with_max_size(self.limits.max_message_bytes);
		let mut rpc: Vec<serde_json::Value> = Vec::new();
		while let Some(frame) = decoder
			.decode_eof(&mut buffered)
			.map_err(|_| self.denial("initialize-response"))?
		{
			if let tokio_sse_codec::Frame::Event(event) = frame {
				if event.name != "message" {
					return Err(self.denial("initialize-response"));
				}
				rpc.push(
					serde_json::from_slice(&event.data).map_err(|_| self.denial("initialize-response"))?,
				);
			}
		}
		if rpc.len() != 1
			|| rpc[0]["id"] != serde_json::to_value(id).expect("RPC id serializes")
			|| !rpc[0]["result"]["capabilities"].is_object()
			|| !rpc[0]["result"]["protocolVersion"].is_string()
		{
			return Err(self.denial("initialize-response"));
		}
		self.check().await?;
		if let Some(capabilities) = rpc[0]["result"]["capabilities"].as_object_mut() {
			for name in ["experimental", "extensions", "logging", "completions"] {
				capabilities.remove(name);
			}
			if self.limits.tasks.is_none() {
				capabilities.remove("tasks");
			}
			for name in ["tools", "resources", "prompts"] {
				if let Some(capability) = capabilities.get_mut(name).and_then(|v| v.as_object_mut()) {
					capability.remove("listChanged");
					if name == "resources" && self.binding.is_some() {
						// Retain only the negotiated upstream/gateway capability.
					} else {
						capability.remove("subscribe");
					}
				}
			}
		}
		let output = format!(
			"data: {}\n\n",
			serde_json::to_string(&rpc[0]).expect("validated JSON")
		);
		Ok(Response::from_parts(parts, Body::from(output)))
	}
}

fn http_for_authorization(access: &SessionAccess) -> ::http::Request<()> {
	(*access.authorization_request).clone()
}

pub(crate) fn deny(action: &ActionRequest, rule: &str) -> ProxyError {
	use security_audit::AuditSink;
	let decision = Decision {
		approval: None,
		request_id: action.request_id.clone(),
		effect: DecisionEffect::Deny,
		policy_id: Some(format!("mcp-session:{rule}")),
		policy_version: None,
		expires_at: None,
	};
	crate::security_events::UiSecurityAuditSink.record(security_audit::event_from_decision(
		uuid::Uuid::new_v4().to_string(),
		action,
		&decision,
	));
	ProxyError::AuthorizationFailed
}

/// Only responses to this POST's RPC may be disclosed. No implicit subscriptions/reverse RPC.
pub(crate) async fn protect_messages(
	stream: Messages,
	context: &super::upstream::IncomingRequestContext,
	request: Option<&rmcp::model::JsonRpcRequest<rmcp::model::ClientRequest>>,
	server: &str,
) -> Messages {
	protect_messages_with_sampling(
		stream,
		context,
		request,
		server,
		#[cfg(feature = "gateway-llm")]
		None,
	)
	.await
}
pub(crate) async fn protect_messages_with_sampling(
	stream: Messages,
	context: &super::upstream::IncomingRequestContext,
	request: Option<&rmcp::model::JsonRpcRequest<rmcp::model::ClientRequest>>,
	server: &str,
	#[cfg(feature = "gateway-llm")] sampling: Option<reverse::sampling::Transport>,
) -> Messages {
	#[cfg(feature = "gateway-llm")]
	let sampling = sampling.map(Arc::new);
	let http = context.as_request();
	let Some(access) = http.extensions().get::<SessionAccess>().cloned() else {
		return stream;
	};
	use rmcp::model::GetMeta;
	let progress_token = request.and_then(|r| r.request.get_meta().get_progress_token());
	let expected = request.map(|r| r.id.clone());
	let method = request.map(|r| r.request.method().to_string());
	let subscription = http.extensions().get::<subscriptions::Ticket>().cloned();
	let task = http.extensions().get::<tasks::Ticket>().cloned();
	let server = server.to_string();
	let business = request.and_then(|r| {
		let op = super::security::normalize(
			r,
			http
				.extensions()
				.get::<security_types::RequestContext>()
				.expect("MCP ingress context")
				.request_id(),
			access.identity.clone(),
			&server,
		);
		match op.kind {
			super::security::OperationKind::Control | super::security::OperationKind::Unsupported => None,
			_ => Some(Arc::new((op.action, op.arguments))),
		}
	});
	let parent = if let Some(task) = &task {
		reverse::task_parent(&access, &server, request, task).await
	} else {
		reverse::parent(&access, &server, request, business.clone())
	};
	Messages::from_stream(futures_util::stream::try_unfold(
		(stream, access, false, parent),
		move |(mut stream, access, done, parent)| {
			#[cfg(feature = "gateway-llm")]
			let sampling = sampling.clone();
			let (expected, business) = (expected.clone(), business.clone());
			let method = method.clone();
			let progress_token = progress_token.clone();
			let subscription = subscription.clone();
			let task = task.clone();
			let server = server.clone();
			async move {
				let parent = parent.map_err(ClientError::new)?;
				if done {
					return Ok(None);
				}
				access.check().await.map_err(ClientError::new)?;
				if let Some(task) = &task {
					task.check(&access).await.map_err(ClientError::new)?;
				}
				reverse::check_parent(&access, parent.as_ref()).map_err(ClientError::new)?;
				let deadline =
					tokio::time::Instant::now() + Duration::from_secs(access.limits.stream_idle_seconds);
				loop {
					let mut message = loop {
						let message = access
							.checked_wait(stream.next(), deadline, || {
								Box::pin(async {
									access.check().await?;
									if let Some(task) = &task {
										task.check(&access).await?;
									}
									reverse::check_parent(&access, parent.as_ref())
								})
							})
							.await
							.map_err(ClientError::new)?;
						let Some(message) = message else {
							return Ok(None);
						};
						let mut message = message?;
						#[cfg(feature = "gateway-llm")]
						if task.is_some() && reverse::sampling::is_request(&message) {
							reverse::request(&access, parent.as_ref(), &mut message)
								.await
								.map_err(ClientError::new)?;
							Box::pin(reverse::sampling::execute(
								&access,
								parent.as_ref(),
								&message,
								sampling.as_deref(),
							))
							.await
							.map_err(ClientError::new)?;
							access.record_activity().await.map_err(ClientError::new)?;
							continue;
						}
						break message;
					};
					access.check().await.map_err(ClientError::new)?;
					if let Some(task) = &task {
						task.check(&access).await.map_err(ClientError::new)?;
					}
					reverse::check_parent(&access, parent.as_ref()).map_err(ClientError::new)?;
					if let Some(business) = &business {
						let (action, args) = business.as_ref();
						let security = access.security();
						Box::pin(super::dispatch::authorize(
							http_for_authorization(&access),
							&action,
							security.authorize_async(action, args.as_ref()),
						))
						.await
						.map_err(ClientError::new)?
						.map_err(|_| ClientError::new(access.denial("business-authorization")))?;
						if let Some(flow) = &access.flow {
							let destination =
								if action.action.action_type == security_types::ActionType::ToolInvoke {
									format!("{server}/{}", action.resource.id)
								} else {
									server.clone()
								};
							if action.action.action_type != security_types::ActionType::ToolList {
								flow
									.check_async(&action, &destination)
									.await
									.map_err(ClientError::new)?;
							}
						}
					}
					access.current().await.map_err(ClientError::new)?;
					reverse::check_parent(&access, parent.as_ref()).map_err(ClientError::new)?;
					use rmcp::model::ServerJsonRpcMessage;
					if security_audit::StateJournal::encoded_len(&message, access.limits.max_message_bytes)
						.is_err()
					{
						return Err(ClientError::new(access.denial("message-limit")));
					}
					let valid = match &mut message {
						ServerJsonRpcMessage::Request(_) => {
							reverse::request(&access, parent.as_ref(), &mut message)
								.await
								.map_err(ClientError::new)?;
							true
						},
						ServerJsonRpcMessage::Response(r) => {
							if let Some(task) = &task {
								if expected.as_ref() != Some(&r.id) {
									return Err(ClientError::new(access.denial("task-response-id")));
								}
								task
									.response(&access, &mut r.result)
									.await
									.map_err(ClientError::new)?;
								if security_audit::StateJournal::encoded_len(
									&message,
									access.limits.max_message_bytes,
								)
								.is_err()
								{
									return Err(ClientError::new(access.denial("task-message-limit")));
								}
								access.record_activity().await.map_err(ClientError::new)?;
								return Ok(Some((message, (stream, access, true, Ok(parent)))));
							}
							use rmcp::model::ServerResult::*;
							if let (Some(flow), ListToolsResult(list)) = (&access.flow, &mut r.result) {
								let mut visible = Vec::with_capacity(list.tools.len());
								for tool in std::mem::take(&mut list.tools) {
									let action = security_pipeline::tool_invoke_for_identity(
										access.action.request_id.clone(),
										access.identity.clone(),
										tool.name.to_string(),
									);
									if flow
										.check_async(&action, &format!("{server}/{}", tool.name))
										.await
										.is_ok()
									{
										visible.push(tool);
									}
								}
								list.tools = visible;
							}
							let kind_matches = matches!(
								(method.as_deref(), &r.result),
								(Some("initialize"), InitializeResult(_))
									| (Some("server/discover"), DiscoverResult(_))
									| (Some("ping"), EmptyResult(_))
									| (Some("tools/call"), CallToolResult(_))
									| (Some("tools/list"), ListToolsResult(_))
									| (Some("resources/list"), ListResourcesResult(_))
									| (
										Some("resources/templates/list"),
										ListResourceTemplatesResult(_)
									) | (Some("resources/read"), ReadResourceResult(_))
									| (Some("prompts/list"), ListPromptsResult(_))
									| (Some("prompts/get"), GetPromptResult(_))
									| (
										Some("resources/subscribe" | "resources/unsubscribe"),
										EmptyResult(_)
									)
							);
							if let rmcp::model::ServerResult::InitializeResult(init) = &mut r.result {
								tasks::observe_initialize(&access, &server, init)
									.await
									.map_err(ClientError::new)?;
								access.restrict_advertised_capabilities(&mut init.capabilities);
							}
							if let rmcp::model::ServerResult::DiscoverResult(discovery) = &mut r.result {
								session_capabilities(&mut discovery.capabilities, false);
							}
							if let rmcp::model::ServerResult::ListToolsResult(list) = &mut r.result {
								tasks::observe_tools(&access, &server, list)
									.await
									.map_err(ClientError::new)?;
							}
							kind_matches && expected.as_ref() == Some(&r.id)
						},
						ServerJsonRpcMessage::Error(e) => {
							e.error.data = None;
							if task.is_some() {
								e.error.message = "asynchronous Task operation failed".into();
							}
							expected
								.as_ref()
								.is_some_and(|id| e.id.as_ref() == Some(id))
						},
						ServerJsonRpcMessage::Notification(n) => {
							// Bound before dropping unrelated messages, and retain the original idle deadline.
							match &n.notification {
								rmcp::model::ServerNotification::ProgressNotification(p)
									if progress_token.as_ref() == Some(&p.params.progress_token) =>
								{
									true
								},
								rmcp::model::ServerNotification::ResourceUpdatedNotification(_)
									if expected.is_none() =>
								{
									subscriptions::notification(&access, &server, &message)
										.await
										.map_err(ClientError::new)?
								},
								// Logging, unrelated progress, and upstream Task identifiers are not grants.
								// They cannot terminate the request or bypass subscription/object authorization.
								_ => {
									tokio::task::yield_now().await;
									continue;
								},
							}
						},
					};
					if !valid {
						return Err(ClientError::new(
							access.denial("unsupported-server-message"),
						));
					}
					if let ServerJsonRpcMessage::Notification(n) = &mut message
						&& let rmcp::model::ServerNotification::ResourceUpdatedNotification(n) =
							&mut n.notification
					{
						n.params.meta = None;
					}
					if serde_json::to_vec(&message)
						.map_err(ClientError::new)?
						.len() > access.limits.max_message_bytes
					{
						return Err(ClientError::new(access.denial("message-limit")));
					}
					if matches!(message, ServerJsonRpcMessage::Response(_))
						&& let Some(ticket) = &subscription
					{
						ticket.commit(&access).await?;
					}
					let done = matches!(
						message,
						ServerJsonRpcMessage::Response(_) | ServerJsonRpcMessage::Error(_)
					) && expected.is_some();
					access.record_activity().await.map_err(ClientError::new)?;
					return Ok(Some((message, (stream, access, done, Ok(parent)))));
				}
			}
		},
	))
}

/// Bound framing *before* the legacy SSE parser can accumulate unbounded input.
pub(crate) fn bound_upstream(
	response: &mut Response,
	ctx: &super::upstream::IncomingRequestContext,
) -> Result<(), ClientError> {
	let request = ctx.as_request();
	let Some(access) = request.extensions().get::<SessionAccess>().cloned() else {
		return Ok(());
	};
	if response
		.headers()
		.get(http::header::CONTENT_ENCODING)
		.is_some_and(|v| v != "identity")
	{
		return Err(ClientError::new(access.denial("compressed-response")));
	}
	if !response
		.headers()
		.get(http::header::CONTENT_TYPE)
		.is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"))
	{
		return Ok(());
	}
	let body = std::mem::replace(response.body_mut(), Body::empty());
	let reader =
		tokio_util::io::StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
	let frames = tokio_util::codec::FramedRead::new(
		reader,
		tokio_sse_codec::SseDecoder::<bytes::Bytes>::with_max_size(access.limits.max_message_bytes),
	);
	let stream =
		futures_util::stream::try_unfold((frames, access), |(mut frames, access)| async move {
			let mut processed = 0;
			loop {
				if processed == 64 {
					tokio::task::yield_now().await;
					processed = 0;
				}
				processed += 1;
				let Some(frame) = frames.next().await else {
					return Ok::<_, std::io::Error>(None);
				};
				let frame = frame.map_err(|_| std::io::Error::other(access.denial("message-limit")))?;
				if let tokio_sse_codec::Frame::Event(event) = frame {
					if event.name != "message" {
						return Err(std::io::Error::other(access.denial("unsupported-event")));
					}
					let data = std::str::from_utf8(&event.data).map_err(std::io::Error::other)?;
					let output = format!("data: {}\n\n", data.replace('\n', "\ndata: "));
					return Ok(Some((bytes::Bytes::from(output), (frames, access))));
				}
			}
		});
	*response.body_mut() = Body::from_stream(stream);
	Ok(())
}
