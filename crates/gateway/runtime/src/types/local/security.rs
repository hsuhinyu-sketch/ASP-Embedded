//! Only typed policy declarations participate in security preparation. Business JSON is opaque here.
use super::*;
use security_integration_runtime::{SecurityConfig, dependency_egress::DependencyEgressConfig};

impl LocalConfig {
	pub(super) fn validate_restricted_payloads(
		&self,
		config: &crate::Config,
	) -> anyhow::Result<bool> {
		let Some(system) = self.ai_systems.iter().find(|system| {
			system
				.security
				.as_ref()
				.and_then(|security| security.cross_component.as_ref())
				.is_some_and(|flow| flow.restrict_untrusted_payloads)
		}) else {
			return Ok(false);
		};
		let setting = "crossComponent.restrictUntrustedPayloads";
		if self.ai_systems.len() != 1
			|| self.llm.is_some()
			|| self.mcp.is_some()
			|| !self.binds.is_empty()
			|| !self.route_groups.is_empty()
			|| !self.backends.is_empty()
			|| !self.policies.is_empty()
			|| !self.services.is_empty()
			|| !self.workloads.is_empty()
			|| system.a2a.is_some()
		{
			bail!("{setting} requires a dedicated RAG and direct LLM instance");
		}
		if self.frontend_policies.connect.is_some()
			|| self.frontend_policies.tracing.is_some()
			|| self.frontend_policies.access_log.is_some()
			|| config.tracing.is_some()
			|| config.database.is_some()
			|| !config.logging.fields.add.is_empty()
			|| !config.metrics.metric_fields.add.is_empty()
		{
			bail!("{setting} does not support CONNECT or custom request telemetry");
		}
		#[cfg(not(all(feature = "gateway-rag", feature = "gateway-llm")))]
		bail!("{setting} requires the RAG and LLM gateway components");
		#[cfg(all(feature = "gateway-rag", feature = "gateway-llm"))]
		{
			use security_integration_runtime::dependency_egress::DependencyKind as D;
			let (Some(llm), Some(rag)) = (&system.llm, &system.rag) else {
				bail!("{setting} requires both RAG and LLM listeners");
			};
			let security = system
				.security
				.as_ref()
				.expect("strict policy belongs to this system");
			if let Some(mcp) = &system.mcp {
				validate_restricted_mcp(mcp, security)
					.with_context(|| format!("{setting} MCP configuration"))?;
			}
			let Some(policies) = &llm.policies else {
				bail!("{setting} requires strict LLM jwtAuth");
			};
			let gateway = &policies.gateway;
			if !gateway.jwt_auth.as_ref().is_some_and(|jwt| jwt.is_strict()) {
				bail!("{setting} requires strict LLM jwtAuth");
			}
			if gateway.ext_proc.is_some()
				|| gateway.ext_authz.is_some()
				|| gateway.oidc.is_some()
				|| policies.remote_rate_limit.is_some()
				|| policies.guardrails.is_some()
				|| policies.inference_routing.is_some()
				|| system
					.inference
					.as_ref()
					.is_some_and(|inference| inference.routing.is_some())
			{
				bail!("{setting} does not support external request processors or endpoint pickers");
			}
			if !llm.virtual_models.is_empty()
				|| !llm.providers.is_empty()
				|| llm.models.is_empty()
				|| llm.models.iter().any(|model| {
					!matches!(model.provider, llm_config::LocalModelAIProvider::OpenAI)
						|| model.params.base_url.is_none()
						|| model.passthrough.is_some()
						|| model.backend_tunnel.is_some()
						|| model.guardrails.is_some()
						|| model
							.auth
							.as_ref()
							.is_some_and(|auth| !matches!(auth, BackendAuth::Key { .. }))
				}) {
				bail!("{setting} requires direct OpenAI-compatible models with a fixed baseUrl");
			}
			if config.dependency_egress.is_none() && security.dependency_egress.is_none() {
				bail!("{setting} requires dependencyEgress for RAG services");
			}
			for egress in config
				.dependency_egress
				.iter()
				.chain(&security.dependency_egress)
			{
				egress
					.check_url(D::Embedding, &rag.gateway.embedding.endpoint)
					.map_err(anyhow::Error::msg)?;
				egress
					.check_url(D::Qdrant, &rag.gateway.qdrant.endpoint)
					.map_err(anyhow::Error::msg)?;
				for source in &rag.gateway.trusted_sources {
					egress
						.check_url(D::TrustedSource, &source.base_url)
						.map_err(anyhow::Error::msg)?;
				}
			}
			Ok(true)
		}
	}
}

#[cfg(all(feature = "gateway-rag", feature = "gateway-llm"))]
fn validate_restricted_mcp(
	mcp: &LocalSimpleMcpConfig,
	security: &SecurityConfig,
) -> anyhow::Result<()> {
	let [target] = mcp.backend.targets.as_slice() else {
		bail!("requires one fixed MCP target");
	};
	let LocalMcpTargetSpec::Mcp { backend } = &target.spec else {
		bail!("requires a Streamable HTTP MCP target");
	};
	if !matches!(backend.process()?, ProcessedMcpBackendHost::Inline { backend: Target::Address(addr), .. } if addr.port() != 0)
		|| target.policies.is_some()
		|| !matches!(mcp.backend.stateful_mode, McpStatefulMode::Stateful)
		|| mcp
			.backend
			.failure_mode
			.is_some_and(|mode| !matches!(mode, FailureMode::FailClosed))
	{
		bail!(
			"requires a fixed IP and port, stateful transport and failClosed without target policies"
		);
	}
	if !security
		.mcp_sessions
		.as_ref()
		.is_some_and(|limits| limits.tasks.is_none() && limits.reverse.is_none())
	{
		bail!("requires mcpSessions with Task and reverse interactions disabled");
	}
	if !matches!(
		&mcp.policies,
		Some(FilterOrPolicy {
			jwt_auth: Some(jwt),
			request_header_modifier: None,
			response_header_modifier: None,
			request_redirect: None,
			url_rewrite: None,
			request_mirror: None,
			direct_response: None,
			cors: None,
			mcp_authorization: None,
			mcp_guardrails: None,
			security_pipeline: None,
			authorization: None,
			mcp_authentication: None,
			a2a: None,
			ai: None,
			backend_tls: None,
			backend_tunnel: None,
			backend_auth: None,
			local_rate_limit: None,
			remote_rate_limit: None,
			oidc: None,
			basic_auth: None,
			api_key: None,
			ext_authz: None,
			ext_proc: None,
			transformations: None,
			csrf: None,
			buffer: None,
			timeout: None,
			retry: None,
		}) if jwt.is_strict()
	) {
		bail!("requires strict MCP jwtAuth as the sole listener policy");
	}
	Ok(())
}

impl NormalizedLocalConfig {
	pub(super) fn validate_restricted_payload_scope(&self, dedicated: bool) -> anyhow::Result<()> {
		if !dedicated
			&& self.security_configs().iter().any(|security| {
				security
					.cross_component
					.as_ref()
					.is_some_and(|flow| flow.restrict_untrusted_payloads)
			}) {
			bail!("crossComponent.restrictUntrustedPayloads must be set on the dedicated AI system");
		}
		Ok(())
	}

	pub(super) async fn prepare_security(
		&mut self,
		parent: Option<&DependencyEgressConfig>,
	) -> anyhow::Result<()> {
		let configs = self.security_configs();
		// Check every declared dependency before readiness can send even a non-sensitive probe.
		if let Some(parent) = parent {
			for config in &configs {
				config
					.check_dependency_endpoints(parent)
					.map_err(anyhow::Error::msg)?;
			}
			#[cfg(feature = "gateway-rag")]
			for system in &self.rag_systems {
				system
					.security
					.check_dependency_endpoints(parent)
					.map_err(anyhow::Error::msg)?;
			}
		}
		for config in configs {
			if let Some(flow) = &config.cross_component {
				flow
					.prepare_store_async()
					.await
					.map_err(anyhow::Error::msg)?;
			}
			config.validate_composition().map_err(anyhow::Error::msg)?;
			#[cfg(feature = "security-pii")]
			if let Some(pii) = &config.pii {
				config
					.pii_runtime
					.prepare(pii)
					.await
					.map_err(anyhow::Error::msg)?;
			}
			config.configuration_digest().map_err(anyhow::Error::msg)?;
			tokio::task::spawn_blocking(move || config.prepare_execution())
				.await
				.map_err(|_| anyhow!("security configuration preparation failed"))?
				.map_err(anyhow::Error::msg)?;
		}
		// RAG-only declarations have no route policy entry. Prepare their owned security
		// here as well so CLI validation and live publication have the same boundary.
		#[cfg(feature = "gateway-rag")]
		for system in &mut self.rag_systems {
			if let Some(flow) = &system.security.cross_component {
				flow
					.prepare_store_async()
					.await
					.map_err(anyhow::Error::msg)?;
			}
			let security = std::mem::take(&mut system.security);
			system.security = tokio::task::spawn_blocking(move || {
				security.prepare_execution()?;
				Ok::<_, String>(security)
			})
			.await
			.map_err(|_| anyhow!("security configuration preparation failed"))?
			.map_err(anyhow::Error::msg)?;
		}
		Ok(())
	}

	fn security_configs(&self) -> Vec<Arc<SecurityConfig>> {
		let mut configs = Vec::new();
		let mut seen = HashSet::new();
		let mut add = |policy: &BackendTrafficPolicy| {
			let config = match policy {
				BackendTrafficPolicy::SecurityAudit(config) => config,
				BackendTrafficPolicy::SecurityPipeline(config) => config.configuration(),
				_ => return,
			};
			if seen.insert(Arc::as_ptr(config)) {
				configs.push(config.clone());
			}
		};
		for policy in &self.policies {
			match &policy.policy {
				PolicyType::Backend(policy) => add(policy),
				PolicyType::Frontend(FrontendPolicy::Tracing(tracing)) => {
					for policy in &tracing.config.policies {
						add(policy);
					}
				},
				_ => {},
			}
		}
		for backend in &self.backends {
			for policy in &backend.inline_policies {
				add(policy);
			}
			#[cfg(feature = "gateway-llm")]
			match &backend.backend {
				Backend::AI(_, ai) => {
					for provider in ai.providers.all_endpoints() {
						for policy in &provider.inline_policies {
							add(policy);
						}
					}
				},
				Backend::LLMRouter(_, router) => {
					for policy in router.backend_policies() {
						add(policy);
					}
				},
				_ => {},
			}
		}
		for (_, routes) in self.listener_routes.iter().chain(self.route_groups.iter()) {
			for route in routes {
				for backend in &route.backends {
					for policy in &backend.inline_policies {
						add(policy);
					}
				}
			}
		}
		for (_, routes) in &self.listener_tcp_routes {
			for route in routes {
				for backend in &route.backends {
					for policy in &backend.inline_policies {
						add(policy);
					}
				}
			}
		}
		configs
	}
}

#[cfg(test)]
#[path = "security/tests.rs"]
mod tests;
