//! Compatibility for legacy top-level access logging and tracing configuration.

use std::sync::Arc;

use anyhow::Context;
use http::Uri;
use platform_core::strng;

use crate::http::backendtls::ResolvedBackendTLS;
use crate::http::transformation_cel::{self, Transformation};
use crate::serdes;
use crate::telemetry::trc::{self, Protocol};
use crate::types::agent::{
	BackendTrafficPolicy, SimpleBackendReference, Target, TracingConfig, TracingProtocol,
};
use crate::types::frontend;

use super::LocalFrontendPolicies;

pub fn migrate_deprecated_local_config(s: &str) -> anyhow::Result<String> {
	let cfg: serde_json::Value = serdes::yamlviajson::from_str(s)?;
	let cfg = migrate_deprecated_frontend_policies(cfg)?;
	serdes::yamlviajson::to_string(&cfg)
}

fn migrate_deprecated_frontend_policies(
	mut cfg: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
	let Some(root) = cfg.as_object_mut() else {
		return Ok(cfg);
	};

	let Some(config) = root.get("config").and_then(serde_json::Value::as_object) else {
		return Ok(cfg);
	};

	let deprecated_logging = config.get("logging").cloned();
	let deprecated_tracing = config.get("tracing").cloned();
	if deprecated_logging.is_none() && deprecated_tracing.is_none() {
		return Ok(cfg);
	}

	let mut deprecated_config = serde_json::Map::new();
	if let Some(logging) = deprecated_logging {
		deprecated_config.insert("logging".to_string(), logging);
	}
	if let Some(tracing) = deprecated_tracing {
		deprecated_config.insert("tracing".to_string(), tracing);
	}
	let mut deprecated_root = serde_json::Map::new();
	deprecated_root.insert(
		"config".to_string(),
		serde_json::Value::Object(deprecated_config),
	);
	let deprecated_cfg_yaml =
		serdes::yamlviajson::to_string(&serde_json::Value::Object(deprecated_root))?;
	let deprecated_cfg = crate::config::parse_config(deprecated_cfg_yaml, None)?;

	let mut frontend_policies: LocalFrontendPolicies = serde_json::from_value(
		root
			.get("frontendPolicies")
			.cloned()
			.unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
	)?;
	merge_deprecated_frontend_policies(&deprecated_cfg, &mut frontend_policies)?;

	let has_deprecated_log = has_deprecated_frontend_log_fields(&deprecated_cfg.logging);
	let has_deprecated_tracing = deprecated_cfg.tracing.is_some();

	let frontend_policies_map = root
		.entry("frontendPolicies")
		.or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
	let Some(frontend_policies_map) = frontend_policies_map.as_object_mut() else {
		anyhow::bail!("frontendPolicies must be an object");
	};
	if has_deprecated_log {
		let Some(access_log) = frontend_policies.access_log else {
			anyhow::bail!("internal error: migrated accessLog was not generated");
		};
		frontend_policies_map.insert("accessLog".to_string(), serde_json::to_value(access_log)?);
		frontend_policies_map.remove("logging");
	}
	if has_deprecated_tracing && let Some(tracing) = frontend_policies.tracing {
		frontend_policies_map.insert("tracing".to_string(), serde_json::to_value(tracing)?);
	}

	let Some(config) = root
		.get_mut("config")
		.and_then(serde_json::Value::as_object_mut)
	else {
		return Ok(cfg);
	};
	if has_deprecated_log {
		match config.get_mut("logging") {
			Some(serde_json::Value::Object(logging)) => {
				logging.remove("filter");
				logging.remove("fields");
				if logging.is_empty() {
					config.remove("logging");
				}
			},
			Some(_) => {
				config.remove("logging");
			},
			None => {},
		}
	}
	if has_deprecated_tracing {
		config.remove("tracing");
	}
	Ok(cfg)
}

fn has_deprecated_frontend_log_fields(log: &crate::telemetry::log::Config) -> bool {
	!log.fields.add.is_empty() || !log.fields.remove.is_empty() || log.filter.is_some()
}

pub(super) fn merge_deprecated_frontend_policies(
	deprecated: &crate::Config,
	frontend_policies: &mut LocalFrontendPolicies,
) -> anyhow::Result<()> {
	let log = &deprecated.logging;
	let has_deprecated_log = has_deprecated_frontend_log_fields(log);
	if has_deprecated_log {
		if frontend_policies.access_log.is_some() {
			anyhow::bail!(
				"cannot use deprecated config.logging together with frontendPolicies.accessLog"
			);
		}
		frontend_policies.access_log = Some(frontend::LoggingPolicy {
			filter: log.filter.clone(),
			add: log.fields.add.clone(),
			remove: log.fields.remove.clone(),
			otlp: None,
			database: None,
			access_log_policy: None,
		});
	}
	if let Some(tracing) = deprecated.tracing.clone() {
		if frontend_policies.tracing.is_some() {
			anyhow::bail!("cannot use deprecated config.tracing together with frontendPolicies.tracing");
		}
		let trc::DeprecatedConfig {
			endpoint,
			headers,
			protocol,
			fields,
			random_sampling,
			client_sampling,
			path,
		} = tracing;

		let mut policies = if !headers.is_empty() {
			let backend_xfm = transformation_cel::LocalTransformationConfig {
				request: Some(transformation_cel::LocalTransform {
					set: headers
						.into_iter()
						.map(|(k, v)| (strng::new(k), strng::new(v)))
						.collect(),
					..Default::default()
				}),
				response: None,
			};
			let backend_xfm = Transformation::try_from_local_config(backend_xfm, true)?;
			vec![BackendTrafficPolicy::Transformation(Arc::new(backend_xfm))]
		} else {
			Vec::new()
		};
		if let Some(ep) = endpoint {
			let (backend, use_tls) = parse_deprecated_tracing_endpoint(&ep)
				.with_context(|| format!("failed parsing tracing endpoint: {}", ep))?;
			if use_tls {
				policies.push(BackendTrafficPolicy::BackendTLS(
					ResolvedBackendTLS::default().try_into()?,
				));
			}
			frontend_policies.tracing = Some(TracingConfig {
				provider_backend: SimpleBackendReference::InlineBackend(backend),
				policies,
				attributes: Arc::unwrap_or_clone(fields.add),
				resources: Default::default(), // Not supported in the old config
				filter: None,                  // Not supported in the old config
				remove: Arc::unwrap_or_clone(fields.remove).into_iter().collect(),
				random_sampling,
				client_sampling,
				path,
				protocol: match protocol {
					Protocol::Grpc => TracingProtocol::Grpc,
					Protocol::Http => TracingProtocol::Http,
				},
			});
		}
	}
	Ok(())
}

fn parse_deprecated_tracing_endpoint(endpoint: &str) -> anyhow::Result<(Target, bool)> {
	if !endpoint.contains("://") {
		return Ok((Target::try_from(endpoint)?, false));
	}

	let uri = Uri::try_from(endpoint)?;
	let Some(scheme) = uri.scheme_str() else {
		return Ok((Target::try_from(endpoint)?, false));
	};
	if !matches!(scheme, "http" | "https" | "grpc") {
		anyhow::bail!("unsupported tracing endpoint scheme: {scheme}");
	}
	let host = uri
		.host()
		.with_context(|| format!("tracing endpoint {endpoint} must include a host"))?;
	let port = uri.port_u16().or_else(|| match scheme {
		"http" => Some(80),
		"https" => Some(443),
		"grpc" => Some(4317),
		_ => unreachable!("unsupported tracing endpoint scheme checked above"),
	});
	let Some(port) = port else {
		anyhow::bail!("unsupported tracing endpoint scheme: {scheme}");
	};
	Ok((Target::from((host, port)), scheme == "https"))
}
