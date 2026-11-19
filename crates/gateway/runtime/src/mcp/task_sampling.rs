//! Legacy Task Sampling bridge. Protocol mapping lives in gateway-mcp; protected
//! model dispatch lives in the Host. No downstream result is an execution receipt.
use super::*;
use crate::mcp::upstream::{IncomingRequestContext, UpstreamGroup};
use crate::proxy::model_execution::{self, Guard};

pub(crate) struct Transport {
	pub upstreams: Arc<UpstreamGroup>,
	pub context: IncomingRequestContext,
}

struct ParentGuard {
	parent: Arc<Parent>,
	access: SessionAccess,
}
impl Guard for ParentGuard {
	fn check(&self) -> gateway_protocol_core::execution::ExecutionFuture<'_, (), ProxyError> {
		Box::pin(async move {
			if !self.parent.is_live() {
				return Err(self.access.denial("task-sampling-parent-closed"));
			}
			let task = self
				.parent
				.task
				.as_ref()
				.ok_or(ProxyError::AuthorizationFailed)?;
			for phase in ["request", "respond"] {
				task
					.check(&self.access, "sampling/createMessage", phase)
					.await?;
				authorize_inner(
					&self.access,
					&self.parent.server,
					"sampling/createMessage",
					phase,
					true,
				)
				.await?;
			}
			check_business(&self.access, &self.parent).await
		})
	}

	fn current(&self) -> Result<(), ProxyError> {
		self.access.current_local()?;
		if !self.parent.is_live()
			|| !self
				.parent
				.task
				.as_ref()
				.is_some_and(|task| task.answerable())
		{
			return Err(self.access.denial("task-sampling-parent-closed"));
		}
		Ok(())
	}

	fn correlate(
		&self,
		request_id: String,
	) -> gateway_protocol_core::execution::ExecutionFuture<'_, (), ProxyError> {
		Box::pin(async move {
			self
				.parent
				.task
				.as_ref()
				.ok_or(ProxyError::AuthorizationFailed)?
				.correlate_model(&self.access, request_id)
				.await
		})
	}

	fn denial(&self, reason: &str) -> ProxyError {
		self.access.denial(reason)
	}
}

pub(crate) fn is_request(message: &ServerJsonRpcMessage) -> bool {
	serde_json::to_value(message)
		.ok()
		.is_some_and(|v| v["method"] == "sampling/createMessage")
}

pub(crate) async fn execute(
	access: &SessionAccess,
	parent: Option<&ParentLease>,
	message: &ServerJsonRpcMessage,
	transport: Option<&Transport>,
) -> Result<(), ProxyError> {
	let parent = parent
		.map(|p| p.parent.clone())
		.ok_or(ProxyError::AuthorizationFailed)?;
	let transport = transport.ok_or_else(|| access.denial("task-sampling-no-dispatcher"))?;
	let http = transport.context.as_request();
	let route = http
		.extensions()
		.get::<model_execution::Route>()
		.cloned()
		.ok_or_else(|| access.denial("task-sampling-no-dispatcher"))?;
	let scope = http
		.extensions()
		.get::<crate::execution_budget::ExecutionScope>()
		.cloned()
		.ok_or(ProxyError::AuthorizationFailed)?;
	let cfg = access
		.limits
		.tasks
		.as_ref()
		.and_then(|t| t.sampling.as_ref())
		.ok_or(ProxyError::AuthorizationFailed)?;
	let reverse = access
		.limits
		.reverse
		.as_ref()
		.ok_or(ProxyError::AuthorizationFailed)?;
	let rpc = serde_json::to_value(message).map_err(|_| access.denial("reverse-shape"))?;
	let sampling = gateway_mcp::sampling::Request::parse(
		&rpc["params"],
		&reverse.sampling_models,
		reverse.max_sampling_tokens,
	)
	.map_err(|_| access.denial("reverse-sampling-contract"))?;
	if !sampling.matches_model(&cfg.model) {
		return Err(access.denial("task-sampling-fixed-model"));
	}
	let guard = Arc::new(ParentGuard {
		parent: parent.clone(),
		access: access.clone(),
	});
	guard.check().await?;
	let executor = route.bind(
		model_execution::Target {
			authority: cfg.authority.clone(),
			path: cfg.path.clone(),
			model: cfg.model.clone(),
		},
		model_execution::Binding {
			config: access.config.clone(),
			allowed_models: reverse.sampling_models.clone(),
			scope: scope.clone(),
			revision: access.revision.clone(),
			guards: parent.task.as_ref().and_then(|t| t.model_guards()),
			flow: access.flow.clone(),
			guard: guard.clone(),
		},
	);
	let deadline = (Instant::now() + Duration::from_secs(reverse.timeout_seconds)).min(
		parent
			.task
			.as_ref()
			.ok_or(ProxyError::AuthorizationFailed)?
			.deadline(),
	);
	let generation = async {
		let result = sampling.generate(&executor).await?;
		guard.check().await?;
		let answer = serde_json::from_value(json!({"jsonrpc":"2.0","id":rpc["id"],"result":result}))
			.map_err(|_| access.denial("task-sampling-output-shape"))?;
		let (server, answer, action, ticket) = response_inner(access, answer, true).await?;
		let ticket = ticket.ok_or(ProxyError::AuthorizationFailed)?;
		let mut context = transport.context.clone();
		context
			.extensions_mut()
			.remove::<super::super::tasks::Ticket>();
		context
			.extensions_mut()
			.remove::<crate::execution_budget::BoundInvocation>();
		context
			.extensions_mut()
			.remove::<Arc<super::super::tasks::interaction::Lease>>();
		context.extensions_mut().insert(ticket.clone());
		context
			.extensions_mut()
			.insert(crate::mcp::security::McpEgressContext {
				server: server.clone(),
				action,
				supported: true,
			});
		let send = transport
			.upstreams
			.get(&server)
			.map_err(|_| ProxyError::AuthorizationFailed)?
			.generic_response(answer, &context);
		ticket
			.run(send)
			.await
			.map_err(|_| access.denial("task-sampling-reply-failed"))?;
		Ok(())
	};
	// The same wait drives both the generation and periodic parent authorization, so a
	// generation holding the Context transaction cannot be frozen by its own recheck.
	let run = async {
		access
			.checked_wait(generation, deadline.into(), || guard.check())
			.await?
	};
	scope.run(run).await?
}
