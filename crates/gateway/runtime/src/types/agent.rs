use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hashbrown::Equivalent;
use heck::ToSnakeCase;
use macro_rules_attribute::apply;
use once_cell::sync::Lazy;
use openapiv3::OpenAPI;
use prometheus_client::encoding::EncodeLabelValue;
use regex::Regex;
use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::control::caclient::CaClient;
use crate::http::auth::BackendAuth;
use crate::http::authorization::RuleSet;
use crate::http::{ext_authz, ext_proc, filters, health, remoteratelimit, retry, timeout};
use crate::mcp::{FailureMode, McpAuthorization};
use crate::store::RequestPolicy;
use crate::telemetry::log::OrderedStringMap;
use crate::types::discovery::{NamespacedHostname, Service};
use crate::types::local::{InternalBackend, SimpleLocalBackend};
use crate::types::{agent, backend, frontend};
use crate::*;

pub use super::discovery::IpFamily;
pub use super::listener_tls::{ServerTLSConfig, TLSVersion, parse_cert, parse_key};
pub use super::routing::{
	HeaderMatch, HeaderValueMatch, HostRedirect, HostRedirectOverride, HostnameMatch,
	HostnameMatchRef, ListenerSet, MethodMatch, PathMatch, PathRedirect, QueryMatch, QueryValueMatch,
	Route, RouteBackend, RouteBackendReference, RouteBackendTarget, RouteGroupKey, RouteKey,
	RouteMatch, RouteName, RouteRuleName, RouteSet, SingleRouteMatch, TCPRoute, TCPRouteBackend,
	TCPRouteBackendReference, TCPRouteSet,
};

#[apply(schema_ser_schema!)]
pub struct Bind {
	pub key: BindKey,
	pub address: SocketAddr,
	pub protocol: BindProtocol,
	pub tunnel_protocol: TunnelProtocol,
	/// Controls whether this bind opens an OS listener socket.
	/// `standard` (default) binds the `address`; `internal` does not bind a socket and is only
	/// reachable via in-process routing (e.g. CONNECT tunnel re-entry by other listeners).
	pub mode: BindMode,
	pub listeners: ListenerSet,
}

impl Bind {
	/// An internal bind with no concrete port (address port 0) acts as the wildcard fallback:
	/// it handles CONNECT re-entry for any destination port that no other bind matches by port.
	pub fn is_wildcard(&self) -> bool {
		self.mode == BindMode::Internal && self.address.port() == 0
	}
}

pub type BindKey = Strng;

#[apply(schema_ser_schema!)]
#[derive(Eq, PartialEq)]
pub struct Listener {
	pub key: ListenerKey,
	// User facing name
	#[serde(flatten)]
	pub name: ListenerName,

	/// Can be a wildcard
	pub hostname: Strng,
	pub protocol: ListenerProtocol,
}

impl Listener {
	pub fn matches(&self, hostname: &str) -> bool {
		self.hostname == hostname
			|| self.hostname.is_empty()
			|| (self.hostname.starts_with("*") && hostname.ends_with(&self.hostname[1..]))
	}
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum ListenerProtocol {
	/// HTTP
	HTTP,
	/// HTTPS, terminating TLS then treating as HTTP
	HTTPS(ServerTLSConfig),
	/// TLS (passthrough or termination)
	TLS(Option<ServerTLSConfig>),
	/// Opaque TCP
	TCP,
	HBONE,
}

impl ListenerProtocol {
	pub async fn tls(
		&self,
		tls: Option<&frontend::TLS>,
		ca: Option<&Arc<CaClient>>,
	) -> Option<anyhow::Result<Arc<rustls::ServerConfig>>> {
		match self {
			ListenerProtocol::HTTPS(t) => Some(t.config_for(tls, ca).await),
			ListenerProtocol::TLS(t) => match t.as_ref() {
				Some(t) => Some(t.config_for(tls, ca).await),
				None => None,
			},
			_ => None,
		}
	}

	pub fn allow_insecure_mtls(&self) -> bool {
		match self {
			ListenerProtocol::HTTPS(t) => t.allow_insecure_mtls(),
			ListenerProtocol::TLS(Some(t)) => t.allow_insecure_mtls(),
			_ => false,
		}
	}

	pub fn include_src_identity_for_connection(&self, conn: &rustls::ServerConnection) -> bool {
		match self {
			ListenerProtocol::HTTPS(t) => t.include_src_identity_for_connection(conn),
			ListenerProtocol::TLS(Some(t)) => t.include_src_identity_for_connection(conn),
			_ => true,
		}
	}
}

// Protocol of the entire bind.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, EncodeLabelValue, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[allow(non_camel_case_types)]
pub enum BindProtocol {
	http,
	// Note: TLS can be TLS (passthrough or termination) or HTTPS
	tls,
	tcp,
	/// Auto-detect protocol by peeking at the first byte of each connection.
	/// If the byte is 0x16 (TLS ClientHello), dispatch as `tls`; otherwise as `http`.
	auto,
}

#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq, Hash, EncodeLabelValue)]
pub enum TunnelProtocol {
	#[default]
	Direct,
	HboneWaypoint,
	HboneGateway,
	Proxy,
	Connect,
}

// Controls whether a bind opens an OS listener socket.
#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq, Hash, EncodeLabelValue)]
pub enum BindMode {
	/// Open a listener socket on the bind's address (the normal behavior).
	#[default]
	Standard,
	/// Do not open a socket. The bind is registered for routing only and is reachable
	/// via in-process re-entry (e.g. another listener redirecting CONNECT traffic to it).
	Internal,
}

// Protocol of the request
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, EncodeLabelValue)]
#[allow(non_camel_case_types)]
pub enum TransportProtocol {
	http,
	https,
	hbone,
	tcp,
	tls,
}

pub type ListenerKey = Strng;

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct ListenerName {
	pub gateway_name: Strng,
	pub gateway_namespace: Strng,
	pub listener_name: Strng,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub listener_set: Option<ResourceName>,
}

impl ListenerName {
	pub fn as_gateway_name(&self) -> Strng {
		strng::format!("{}/{}", self.gateway_namespace, self.gateway_name)
	}
	pub fn as_gateway_target_ref(&self) -> PolicyTargetRef {
		PolicyTargetRef::Gateway {
			gateway_name: self.gateway_name.as_ref(),
			gateway_namespace: self.gateway_namespace.as_ref(),
			listener_name: None,
			port: None,
		}
	}
	pub fn as_listener_target_ref(&self) -> PolicyTargetRef {
		PolicyTargetRef::Gateway {
			gateway_name: self.gateway_name.as_ref(),
			gateway_namespace: self.gateway_namespace.as_ref(),
			listener_name: Some(self.listener_name.as_ref()),
			port: None,
		}
	}
	pub fn as_listenerset_target_ref(&self) -> Option<PolicyTargetRef<'_>> {
		self
			.listener_set
			.as_ref()
			.map(|ls| PolicyTargetRef::ListenerSet {
				name: ls.name.as_ref(),
				namespace: ls.namespace.as_ref(),
				section: None,
			})
	}

	pub fn as_listenerset_listener_target_ref(&self) -> Option<PolicyTargetRef<'_>> {
		self
			.listener_set
			.as_ref()
			.map(|ls| PolicyTargetRef::ListenerSet {
				name: ls.name.as_ref(),
				namespace: ls.namespace.as_ref(),
				section: Some(self.listener_name.as_ref()),
			})
	}
}

impl From<ListenerName> for ListenerTarget {
	fn from(l: ListenerName) -> Self {
		Self {
			gateway_name: l.gateway_name.clone(),
			gateway_namespace: l.gateway_namespace.clone(),
			listener_name: Some(l.listener_name.clone()),
			port: None,
		}
	}
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct ListenerTarget {
	pub gateway_name: Strng,
	pub gateway_namespace: Strng,
	pub listener_name: Option<Strng>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub port: Option<u16>,
}

impl ListenerTarget {
	pub fn validate(&self) -> anyhow::Result<()> {
		anyhow::ensure!(
			!(self.listener_name.is_some() && self.port.is_some()),
			"gateway policy target cannot set both listener_name and port"
		);
		Ok(())
	}

	pub fn strip_listener_fields(&self) -> ListenerTarget {
		Self {
			gateway_name: self.gateway_name.clone(),
			gateway_namespace: self.gateway_namespace.clone(),
			listener_name: None,
			port: None,
		}
	}
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct ResourceName {
	pub name: Strng,
	pub namespace: Strng,
}

impl ResourceName {
	pub fn new(name: Strng, namespace: Strng) -> Self {
		Self { name, namespace }
	}
}

impl fmt::Display for ResourceName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/{}", self.namespace, self.name)
	}
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct TypedResourceName {
	pub kind: Strng,
	pub name: Strng,
	pub namespace: Strng,
}

impl fmt::Display for TypedResourceName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/{}/{}", self.kind, self.namespace, self.name)
	}
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub enum BackendTarget {
	Backend {
		name: Strng,
		namespace: Strng,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		section: Option<Strng>,
	},
	Service {
		hostname: Strng,
		namespace: Strng,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		port: Option<u16>,
	},
	Invalid,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum BackendTargetRef<'a> {
	Backend {
		name: &'a str,
		namespace: &'a str,
		section: Option<&'a str>,
	},
	Service {
		hostname: &'a str,
		namespace: &'a str,
		port: Option<u16>,
	},
	Invalid,
}

impl<'a> From<&'a BackendTarget> for BackendTargetRef<'a> {
	fn from(value: &'a BackendTarget) -> Self {
		match value {
			BackendTarget::Backend {
				name,
				namespace,
				section,
			} => BackendTargetRef::Backend {
				name,
				namespace,
				section: section.as_deref(),
			},
			BackendTarget::Service {
				hostname,
				namespace,
				port,
			} => BackendTargetRef::Service {
				hostname,
				namespace,
				port: *port,
			},
			BackendTarget::Invalid => BackendTargetRef::Invalid,
		}
	}
}

impl BackendTargetRef<'_> {
	pub fn strip_section(&self) -> BackendTargetRef {
		match self {
			BackendTargetRef::Backend {
				name, namespace, ..
			} => BackendTargetRef::Backend {
				name,
				namespace,
				section: None,
			},
			BackendTargetRef::Service {
				namespace,
				hostname,
				..
			} => BackendTargetRef::Service {
				namespace,
				hostname,
				port: None,
			},
			BackendTargetRef::Invalid => BackendTargetRef::Invalid,
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendWithPolicies {
	pub backend: Backend,

	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

impl From<SimpleBackendWithPolicies> for BackendWithPolicies {
	fn from(backend: SimpleBackendWithPolicies) -> Self {
		Self {
			backend: Backend::from(backend.backend),
			inline_policies: backend.inline_policies,
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Backend {
	Service(Arc<Service>, u16),
	#[serde(rename = "host", serialize_with = "serialize_backend_tuple")]
	Opaque(ResourceName, Target), // Hostname or IP
	#[serde(rename = "mcp", serialize_with = "serialize_backend_tuple")]
	MCP(ResourceName, McpBackend),
	#[serde(rename = "ai", serialize_with = "serialize_backend_tuple")]
	#[cfg(feature = "gateway-llm")]
	AI(ResourceName, crate::llm::AIBackend),
	#[serde(rename = "llmRouter", serialize_with = "serialize_backend_tuple")]
	#[cfg(feature = "gateway-llm")]
	LLMRouter(ResourceName, Arc<crate::llm::model_router::ModelRouter>),
	#[serde(rename = "aws", serialize_with = "serialize_backend_tuple")]
	Aws(ResourceName, crate::aws::AwsBackendConfig),
	#[serde(serialize_with = "serialize_backend_tuple")]
	Dynamic(ResourceName, ()),
	/// In-process admin service backend. This is only valid for HTTP routes.
	#[serde(serialize_with = "serialize_backend_tuple")]
	Internal(ResourceName, InternalBackend),
	Invalid,
}

impl From<Backend> for BackendWithPolicies {
	fn from(val: Backend) -> Self {
		BackendWithPolicies {
			backend: val,
			inline_policies: vec![],
		}
	}
}

pub fn serialize_backend_tuple<S: Serializer, T: serde::Serialize>(
	name: &ResourceName,
	t: T,
	serializer: S,
) -> Result<S::Ok, S::Error> {
	#[derive(Debug, Clone, serde::Serialize)]
	#[serde(rename_all = "camelCase")]
	struct BackendTuple<'a, T: serde::Serialize> {
		#[serde(flatten)]
		name: &'a ResourceName,
		target: &'a T,
	}
	BackendTuple { name, target: &t }.serialize(serializer)
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BackendReference {
	Service { name: NamespacedHostname, port: u16 },
	Backend(BackendKey),
	Invalid,
}

impl From<SimpleBackend> for Backend {
	fn from(value: SimpleBackend) -> Self {
		match value {
			SimpleBackend::Service(svc, port) => Backend::Service(svc, port),
			SimpleBackend::Opaque(name, target) => Backend::Opaque(name, target),
			SimpleBackend::Aws(name, cfg) => Backend::Aws(name, cfg),
			SimpleBackend::Invalid => Backend::Invalid,
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SimpleBackend {
	Service(Arc<Service>, u16),
	#[serde(rename = "host")]
	Opaque(ResourceName, Target), // Hostname or IP
	Aws(ResourceName, crate::aws::AwsBackendConfig),
	Invalid,
}

impl fmt::Display for SimpleBackend {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			SimpleBackend::Service(service, port) => write!(f, "{}:{}", service.hostname, port),
			SimpleBackend::Opaque(name, _) => write!(f, "{}", name),
			SimpleBackend::Aws(name, _) => write!(f, "{}", name),
			SimpleBackend::Invalid => write!(f, "invalid"),
		}
	}
}

impl TryFrom<Backend> for SimpleBackend {
	type Error = anyhow::Error;

	fn try_from(value: Backend) -> Result<Self, Self::Error> {
		match value {
			Backend::Service(svc, port) => Ok(SimpleBackend::Service(svc, port)),
			Backend::Opaque(name, tgt) => Ok(SimpleBackend::Opaque(name, tgt)),
			Backend::Aws(rn, cfg) => Ok(SimpleBackend::Aws(rn, cfg)),
			Backend::Invalid => Ok(SimpleBackend::Invalid),
			_ => anyhow::bail!("unsupported backend type"),
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimpleBackendWithPolicies {
	pub backend: SimpleBackend,

	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

impl From<SimpleBackend> for SimpleBackendWithPolicies {
	fn from(value: SimpleBackend) -> Self {
		Self {
			backend: value,
			inline_policies: vec![],
		}
	}
}

#[derive(Eq, PartialEq)]
#[apply(schema_ser_schema!)]
#[cfg_attr(feature = "schema", schemars(with = "SimpleLocalBackend"))]
pub enum SimpleBackendReference {
	Service { name: NamespacedHostname, port: u16 },
	Backend(BackendKey),
	InlineBackend(Target),
	Invalid,
}

impl<'de> serde::Deserialize<'de> for SimpleBackendReference {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let slb = SimpleLocalBackend::deserialize(deserializer)?;
		match slb {
			SimpleLocalBackend::Service { name, port } => {
				Ok(SimpleBackendReference::Service { name, port })
			},
			SimpleLocalBackend::Opaque(t) => Ok(SimpleBackendReference::InlineBackend(t)),
			SimpleLocalBackend::Backend(n) => Ok(SimpleBackendReference::Backend(n)),
			SimpleLocalBackend::Invalid => Ok(SimpleBackendReference::Invalid),
		}
	}
}

impl SimpleBackend {
	pub fn hostport(&self) -> String {
		match self {
			SimpleBackend::Service(svc, port) => {
				format!("{}:{port}", svc.hostname)
			},
			SimpleBackend::Aws(_, cfg) => format!("{}:{}", cfg.get_host(), 443),
			SimpleBackend::Opaque(_, tgt) => tgt.hostport(),
			SimpleBackend::Invalid => "invalid".to_string(),
		}
	}

	pub fn target(&self) -> BackendTargetRef {
		match self {
			SimpleBackend::Service(svc, port) => BackendTargetRef::Service {
				hostname: svc.hostname.as_ref(),
				namespace: svc.namespace.as_ref(),
				port: Some(*port),
			},
			SimpleBackend::Opaque(name, _) => BackendTargetRef::Backend {
				name: name.name.as_ref(),
				namespace: name.namespace.as_ref(),
				section: None,
			},
			SimpleBackend::Aws(name, _) => BackendTargetRef::Backend {
				name: name.name.as_ref(),
				namespace: name.namespace.as_ref(),
				section: None,
			},
			SimpleBackend::Invalid => BackendTargetRef::Invalid,
		}
	}

	pub fn backend_type(&self) -> cel::BackendType {
		match self {
			SimpleBackend::Service(_, _) => cel::BackendType::Service,
			SimpleBackend::Opaque(_, _) => cel::BackendType::Static,
			SimpleBackend::Aws(_, _) => cel::BackendType::Dynamic,
			SimpleBackend::Invalid => cel::BackendType::Unknown,
		}
	}

	pub fn backend_info(&self) -> BackendInfo {
		BackendInfo {
			backend_type: self.backend_type(),
			backend_name: strng::format!("{}", self),
		}
	}
}

impl Backend {
	/// Reject control-plane/embedder values that bypass local YAML deserialization.
	pub(crate) fn validate_compiled(&self) -> Result<(), crate::proxy::ProxyError> {
		match self {
			#[cfg(not(feature = "gateway-mcp"))]
			Self::MCP(..) => Err(crate::proxy::ProxyError::ProcessingString(
				"MCP support is not compiled; enable gateway-mcp".into(),
			)),
			#[cfg(not(feature = "providers-aws"))]
			Self::Aws(..) => Err(crate::proxy::ProxyError::ProcessingString(
				"AWS support is not compiled; enable providers-aws".into(),
			)),
			_ => Ok(()),
		}
	}

	pub(crate) fn resource_name(&self) -> Option<&ResourceName> {
		match self {
			Self::Opaque(name, _)
			| Self::MCP(name, _)
			| Self::Aws(name, _)
			| Self::Dynamic(name, _)
			| Self::Internal(name, _) => Some(name),
			#[cfg(feature = "gateway-llm")]
			Self::AI(name, _) | Self::LLMRouter(name, _) => Some(name),
			Self::Service(..) | Self::Invalid => None,
		}
	}

	pub(crate) fn is_llm(&self) -> bool {
		match self {
			#[cfg(feature = "gateway-llm")]
			Self::AI(..) | Self::LLMRouter(..) => true,
			_ => false,
		}
	}

	pub fn target(&self) -> BackendTarget {
		match self {
			Backend::Service(svc, port) => BackendTarget::Service {
				hostname: svc.hostname.clone(),
				namespace: svc.namespace.clone(),
				port: Some(*port),
			},
			backend if backend.resource_name().is_some() => {
				let name = backend.resource_name().expect("named backend");
				BackendTarget::Backend {
					name: name.name.clone(),
					namespace: name.namespace.clone(),
					section: None,
				}
			},
			_ => BackendTarget::Invalid,
		}
	}

	pub fn target_ref(&self) -> BackendTargetRef {
		match self {
			Backend::Service(svc, port) => BackendTargetRef::Service {
				hostname: svc.hostname.as_ref(),
				namespace: svc.namespace.as_ref(),
				port: Some(*port),
			},
			backend if backend.resource_name().is_some() => {
				let name = backend.resource_name().expect("named backend");
				BackendTargetRef::Backend {
					name: name.name.as_ref(),
					namespace: name.namespace.as_ref(),
					section: None,
				}
			},
			_ => BackendTargetRef::Invalid,
		}
	}

	pub fn name(&self) -> Strng {
		match self {
			Backend::Service(svc, port) => strng::format!("{}:{}", svc.hostname.clone(), port),
			backend if backend.resource_name().is_some() => {
				let name = backend.resource_name().expect("named backend");
				let mut s = String::with_capacity(name.namespace.len() + name.name.len() + 1);
				s.push_str(&name.namespace);
				s.push('/');
				s.push_str(&name.name);
				strng::new(&s)
			},
			_ => strng::literal!("invalid"),
		}
	}

	pub fn backend_type(&self) -> cel::BackendType {
		match self {
			Backend::Service(_, _) => cel::BackendType::Service,
			Backend::Opaque(_, _) => cel::BackendType::Static,
			Backend::MCP(_, _) => cel::BackendType::MCP,
			#[cfg(feature = "gateway-llm")]
			Backend::AI(_, _) | Backend::LLMRouter(_, _) => cel::BackendType::AI,
			Backend::Aws(_, _) => cel::BackendType::Unknown,
			Backend::Dynamic(_, _) => cel::BackendType::Dynamic,
			Backend::Internal(_, _) => cel::BackendType::Unknown,
			Backend::Invalid => cel::BackendType::Unknown,
		}
	}

	pub fn backend_protocol(&self) -> Option<cel::BackendProtocol> {
		match self {
			Backend::MCP(_, _) => Some(cel::BackendProtocol::mcp),
			#[cfg(feature = "gateway-llm")]
			Backend::AI(_, _) | Backend::LLMRouter(_, _) => Some(cel::BackendProtocol::llm),
			_ => None,
		}
	}

	pub fn backend_info(&self) -> BackendInfo {
		BackendInfo {
			backend_type: self.backend_type(),
			backend_name: self.name(),
		}
	}
}

#[derive(Debug, Clone)]
pub struct BackendInfo {
	pub backend_type: cel::BackendType,
	pub backend_name: Strng,
}

#[apply(schema_ser_schema!)]
pub struct McpBackend {
	pub targets: Vec<Arc<McpTarget>>,
	pub stateful: bool,
	pub always_use_prefix: bool,
	/// Behavior when one or more MCP targets fail to initialize or fail during fanout.
	/// Defaults to `failClosed`.
	pub failure_mode: FailureMode,
	#[serde(with = "crate::serdes::serde_dur")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	pub session_idle_ttl: Duration,
}

impl McpBackend {
	pub fn find(&self, name: &str) -> Option<Arc<McpTarget>> {
		self
			.targets
			.iter()
			.find(|target| target.name.as_str() == name)
			.cloned()
	}
}

#[apply(schema_ser_schema!)]
pub struct McpTarget {
	pub name: McpTargetName,
	#[serde(flatten)]
	pub spec: McpTargetSpec,
}

pub type McpTargetName = Strng;

// Gateway API SectionName: https://gateway-api.sigs.k8s.io/reference/spec/#sectionname
const MCP_TARGET_NAME_MAX_LEN: usize = 253;

static MCP_TARGET_NAME_RE: Lazy<Regex> = Lazy::new(|| {
	Regex::new(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$").unwrap()
});

pub fn validate_mcp_target_name(name: &str) -> Result<(), String> {
	if name.is_empty() {
		return Err("invalid MCP target name: must not be empty".to_string());
	}
	if name.len() > MCP_TARGET_NAME_MAX_LEN {
		return Err(format!(
			"invalid MCP target name {name:?}: length {} exceeds max {MCP_TARGET_NAME_MAX_LEN}",
			name.len()
		));
	}
	if !MCP_TARGET_NAME_RE.is_match(name) {
		return Err(format!(
			"invalid MCP target name {name:?}: must match Gateway API SectionName pattern (lowercase letters, digits, '-' and '.'; '+' and '_' are reserved MCP delimiters)"
		));
	}
	Ok(())
}

#[apply(schema_ser_schema!)]
pub enum McpTargetSpec {
	#[serde(rename = "sse")]
	Sse(SseTargetSpec),
	#[serde(rename = "mcp")]
	Mcp(StreamableHTTPTargetSpec),
	#[serde(rename = "stdio")]
	Stdio {
		cmd: String,
		#[serde(default, skip_serializing_if = "Vec::is_empty")]
		args: Vec<String>,
		#[serde(default, skip_serializing_if = "HashMap::is_empty")]
		env: HashMap<String, String>,
		#[serde(default, skip_serializing_if = "std::ops::Not::not")]
		clear_env: bool,
	},
	#[serde(rename = "openapi")]
	OpenAPI(OpenAPITarget),
}

impl McpTargetSpec {
	pub fn backend(&self) -> Option<&SimpleBackendReference> {
		match self {
			McpTargetSpec::Sse(s) => Some(&s.backend),
			McpTargetSpec::Mcp(s) => Some(&s.backend),
			McpTargetSpec::OpenAPI(s) => Some(&s.backend),
			McpTargetSpec::Stdio { .. } => None,
		}
	}
}

#[apply(schema_ser_schema!)]
pub struct SseTargetSpec {
	pub backend: SimpleBackendReference,
	pub path: String,
}

#[apply(schema_ser_schema!)]
pub struct StreamableHTTPTargetSpec {
	pub backend: SimpleBackendReference,
	pub path: String,
}

#[apply(schema_ser_schema!)]
pub struct OpenAPITarget {
	pub backend: SimpleBackendReference,
	#[serde(skip_serializing)]
	#[cfg_attr(feature = "schema", schemars(with = "serde_json::value::RawValue"))]
	pub schema: Arc<OpenAPI>,
}

pub type PolicyKey = Strng;
pub type BackendKey = Strng;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetedPolicy {
	pub key: PolicyKey,
	pub name: Option<TypedResourceName>,
	pub target: PolicyTarget,
	#[serde(default, skip_serializing_if = "PolicyInheritance::is_default")]
	pub inheritance: PolicyInheritance,
	pub policy: PolicyType,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyInheritance {
	#[default]
	Default,
	Override,
}

impl PolicyInheritance {
	pub fn is_default(&self) -> bool {
		matches!(self, Self::Default)
	}
}

/// Configuration for dynamic tracing policy
#[apply(schema!)]
pub struct TracingConfig {
	/// Backend that receives exported traces.
	#[serde(flatten)]
	pub provider_backend: SimpleBackendReference,
	/// Backend policies used when exporting traces.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[serde(deserialize_with = "crate::types::local::de_from_local_backend_policy")]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<crate::types::local::SimpleLocalBackendPolicies>")
	)]
	pub policies: Vec<BackendTrafficPolicy>,
	/// Span attributes to add, keyed by attribute name.
	#[serde(default)]
	pub attributes: OrderedStringMap<Arc<cel::Expression>>,
	/// Resource attributes to add to the tracer provider (OTel `Resource`).
	/// This can be used to set things like `service.name` dynamically.
	#[serde(default)]
	pub resources: OrderedStringMap<Arc<cel::Expression>>,
	/// Attribute keys to remove from the emitted span attributes.
	///
	/// This is applied before `attributes` are evaluated/added, so it can be used to drop
	/// default attributes or avoid duplication.
	#[serde(default)]
	pub remove: Vec<String>,
	/// Optional per-policy override for random sampling. If set, overrides global config for
	/// requests that use this frontend policy.
	#[serde(default, deserialize_with = "deserialize_sampling_expr_opt")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<crate::StringBoolFloat>"))]
	pub random_sampling: Option<Arc<cel::Expression>>,
	/// Optional per-policy override for client sampling. If set, overrides global config for
	/// requests that use this frontend policy.
	#[serde(default, deserialize_with = "deserialize_sampling_expr_opt")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<crate::StringBoolFloat>"))]
	pub client_sampling: Option<Arc<cel::Expression>>,
	/// Optional CEL filter with KEEP semantics. When set, only requests for which the expression
	/// evaluates to `true` have their trace span(s) exported; all other spans are dropped. When
	/// unset, no filtering is applied (all sampled spans are exported). Composes after sampling
	/// (only sampled spans are evaluated). This matches `accessLog.filter` (keep-semantics):
	/// `true` keeps. Missing/errored fields evaluate to `false`, so on eval error the span is
	/// dropped (fail closed).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub filter: Option<Arc<cel::Expression>>,
	/// OTLP HTTP path used to export traces.
	#[serde(default = "default_otlp_path")]
	pub path: String,
	/// OTLP protocol used to export traces. Defaults to HTTP.
	#[serde(default)]
	pub protocol: TracingProtocol,
}

fn default_otlp_path() -> String {
	"/v1/traces".to_string()
}

fn deserialize_sampling_expr_opt<'de, D>(
	deserializer: D,
) -> Result<Option<Arc<cel::Expression>>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let v = Option::<crate::StringBoolFloat>::deserialize(deserializer)?;
	v.map(|v| cel::Expression::new_strict(&v.0))
		.transpose()
		.map(|o| o.map(Arc::new))
		.map_err(|e| serde::de::Error::custom(e.to_string()))
}

#[derive(serde::Serialize, serde::Deserialize, Default, Copy, Eq, PartialEq, Clone, Debug)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(crate::JsonSchema))]
pub enum TracingProtocol {
	#[default]
	Grpc,
	Http,
}

/// TracingPolicy holds both the configuration and the compiled OpenTelemetry tracer
#[derive(Clone, Debug)]
pub struct TracingPolicy {
	pub config: TracingConfig,
	/// CEL fields used by the tracer for span attributes. Stored so we can lazily
	/// create the tracer at first use with the correct attribute set.
	pub fields: Arc<crate::telemetry::log::LoggingFields>,
	/// Lazily initialized tracer. Created on first access in the dataplane
	/// using a PolicyClient so that backend routing and auth can be applied.
	#[cfg(feature = "telemetry-otlp")]
	pub tracer: once_cell::sync::OnceCell<Arc<crate::telemetry::trc::Tracer>>,
}

impl serde::Serialize for TracingPolicy {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.config.serialize(serializer)
	}
}

#[cfg(feature = "telemetry-otlp")]
impl TracingPolicy {
	pub fn get_or_init(
		&self,
		policy_client: crate::proxy::httpproxy::PolicyClient,
	) -> anyhow::Result<&Arc<crate::telemetry::trc::Tracer>> {
		self.tracer.get_or_try_init(|| {
			let tracer =
				crate::telemetry::trc::Tracer::new(&self.config, self.fields.clone(), policy_client)?;
			Ok(Arc::new(tracer))
		})
	}
}

#[derive(Clone, Debug)]
pub struct AccessLogPolicy {
	pub config: crate::types::frontend::OtlpLoggingConfig,
	#[cfg(feature = "telemetry-otlp")]
	pub logger: once_cell::sync::OnceCell<Arc<crate::telemetry::log::OtelAccessLogger>>,
}

#[cfg(feature = "telemetry-otlp")]
impl AccessLogPolicy {
	pub fn get_or_init(
		&self,
		policy_client: crate::proxy::httpproxy::PolicyClient,
	) -> anyhow::Result<&Arc<crate::telemetry::log::OtelAccessLogger>> {
		self.logger.get_or_try_init(|| {
			let logger = crate::telemetry::log::OtelAccessLogger::new(
				policy_client,
				self.config.provider_backend.clone(),
				self.config.policies.clone(),
				self.config.protocol,
				self.config.path.clone(),
			)?;
			Ok(Arc::new(logger))
		})
	}
}

impl serde::Serialize for AccessLogPolicy {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.config.serialize(serializer)
	}
}

impl From<BackendTrafficPolicy> for PolicyType {
	fn from(value: BackendTrafficPolicy) -> Self {
		Self::Backend(value)
	}
}

impl From<FrontendPolicy> for PolicyType {
	fn from(value: FrontendPolicy) -> Self {
		Self::Frontend(value)
	}
}

impl From<TrafficPolicy> for PolicyType {
	fn from(value: TrafficPolicy) -> Self {
		// Default to route for simplicity.
		(value, PolicyPhase::Route).into()
	}
}
impl From<(TrafficPolicy, PolicyPhase)> for PolicyType {
	fn from((p, phase): (TrafficPolicy, PolicyPhase)) -> Self {
		Self::Traffic(PhasedTrafficPolicy { phase, policy: p })
	}
}

#[apply(schema!)]
#[derive(Copy, Default, Eq, PartialEq)]
pub enum PolicyPhase {
	#[default]
	Route,
	Gateway,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhasedTrafficPolicy {
	pub phase: PolicyPhase,
	#[serde(flatten)]
	pub policy: TrafficPolicy,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyType {
	Frontend(FrontendPolicy),
	Traffic(PhasedTrafficPolicy),
	Backend(BackendTrafficPolicy),
}

impl PolicyType {
	pub fn as_traffic_gateway_phase(&self) -> Option<&TrafficPolicy> {
		match self {
			PolicyType::Traffic(t) if t.phase == PolicyPhase::Gateway => Some(&t.policy),
			_ => None,
		}
	}
	pub fn as_traffic_route_phase(&self) -> Option<&TrafficPolicy> {
		match self {
			PolicyType::Traffic(t) if t.phase == PolicyPhase::Route => Some(&t.policy),
			_ => None,
		}
	}
	pub fn as_backend(&self) -> Option<&BackendTrafficPolicy> {
		match self {
			PolicyType::Backend(t) => Some(t),
			_ => None,
		}
	}
	pub fn as_frontend(&self) -> Option<&FrontendPolicy> {
		match self {
			PolicyType::Frontend(t) => Some(t),
			_ => None,
		}
	}
}

pub type RouteTarget = RouteName;

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct ListenerSetTarget {
	pub name: Strng,
	pub namespace: Strng,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub section: Option<Strng>,
}

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub enum PolicyTarget {
	Gateway(ListenerTarget),
	Route(RouteTarget),
	Backend(BackendTarget),
	ListenerSet(ListenerSetTarget),
}

impl PolicyTarget {
	pub fn validate(&self) -> anyhow::Result<()> {
		if let PolicyTarget::Gateway(target) = self {
			target.validate()?;
		}
		Ok(())
	}
}

impl Equivalent<PolicyTarget> for PolicyTargetRef<'_> {
	fn equivalent(&self, key: &PolicyTarget) -> bool {
		self == &PolicyTargetRef::from(key)
	}
}

#[derive(Hash, Eq, PartialEq)]
pub enum PolicyTargetRef<'a> {
	Gateway {
		gateway_name: &'a str,
		gateway_namespace: &'a str,
		listener_name: Option<&'a str>,
		port: Option<u16>,
	},
	Route {
		name: &'a str,
		namespace: &'a str,
		rule_name: Option<&'a str>,
		kind: Option<&'a str>,
	},
	Backend(BackendTargetRef<'a>),
	ListenerSet {
		name: &'a str,
		namespace: &'a str,
		section: Option<&'a str>,
	},
}

impl<'a> From<&'a PolicyTarget> for PolicyTargetRef<'a> {
	fn from(value: &'a PolicyTarget) -> Self {
		match value {
			PolicyTarget::Gateway(v) => PolicyTargetRef::Gateway {
				gateway_name: &v.gateway_name,
				gateway_namespace: v.gateway_namespace.as_ref(),
				listener_name: v.listener_name.as_deref(),
				port: v.port,
			},
			PolicyTarget::Route(v) => PolicyTargetRef::Route {
				name: &v.name,
				namespace: v.namespace.as_ref(),
				rule_name: v.rule_name.as_deref(),
				kind: v.kind.as_deref(),
			},
			PolicyTarget::Backend(v) => PolicyTargetRef::Backend(v.into()),
			PolicyTarget::ListenerSet(v) => PolicyTargetRef::ListenerSet {
				name: v.name.as_ref(),
				namespace: v.namespace.as_ref(),
				section: v.section.as_deref(),
			},
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FrontendPolicy {
	#[serde(rename = "http")]
	HTTP(frontend::HTTP),
	#[serde(rename = "tls")]
	TLS(frontend::TLS),
	#[serde(rename = "tcp")]
	TCP(frontend::TCP),
	NetworkAuthorization(frontend::NetworkAuthorization),
	Proxy(frontend::Proxy),
	Connect(frontend::Connect),
	AccessLog(frontend::LoggingPolicy),
	Tracing(Arc<TracingPolicy>),
	Metrics(frontend::MetricsFieldsPolicy),
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrafficPolicy {
	Timeout(timeout::Policy),
	Retry(retry::Policy),
	#[serde(rename = "ai")]
	AI(Arc<llm::Policy>),
	Authorization(Authorization),
	LocalRateLimit(RequestPolicy<Vec<crate::http::localratelimit::RateLimit>>),
	RemoteRateLimit(RequestPolicy<remoteratelimit::RemoteRateLimit>),
	ExtAuthz(RequestPolicy<ext_authz::ExtAuthz>),
	ExtProc(RequestPolicy<ext_proc::ExtProc>),
	JwtAuth(RequestPolicy<JwtAuthentication>),
	Oidc(RequestPolicy<crate::http::oidc::OidcPolicy>),
	BasicAuth(RequestPolicy<crate::http::basicauth::BasicAuthentication>),
	APIKey(RequestPolicy<crate::http::apikey::APIKeyAuthentication>),
	Transformation(RequestPolicy<crate::http::transformation_cel::Transformation>),
	Csrf(RequestPolicy<crate::http::csrf::Csrf>),

	RequestHeaderModifier(RequestPolicy<filters::HeaderModifier>),
	ResponseHeaderModifier(RequestPolicy<filters::HeaderModifier>),
	RequestRedirect(RequestPolicy<filters::RequestRedirect>),
	UrlRewrite(RequestPolicy<filters::UrlRewrite>),
	HostRewrite(agent::HostRedirectOverride),
	RequestMirror(Vec<filters::RequestMirror>),
	DirectResponse(RequestPolicy<filters::DirectResponse>),
	Buffer(RequestPolicy<http::buffer::Buffer>),
	#[serde(rename = "cors")]
	CORS(RequestPolicy<http::cors::Cors>),
}

/// Compatibility declaration normalized once into the shared configuration owner.
/// Its mode cannot be changed; serialization retains the original securityPipeline shape.
#[derive(Debug, Clone)]
pub struct LegacySecurityPipeline(Arc<security_integration_runtime::SecurityConfig>);

impl From<security_pipeline::SecurityPipelineConfig> for LegacySecurityPipeline {
	fn from(pipeline: security_pipeline::SecurityPipelineConfig) -> Self {
		Self(Arc::new(
			security_integration_runtime::SecurityConfig::from(
				security_integration_runtime::SecurityConfigData {
					mode: security_integration_runtime::SecurityMode::Enforce,
					pipeline,
					..Default::default()
				},
			),
		))
	}
}

impl LegacySecurityPipeline {
	pub fn configuration(&self) -> &Arc<security_integration_runtime::SecurityConfig> {
		&self.0
	}
}

impl serde::Serialize for LegacySecurityPipeline {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		self.0.pipeline.serialize(serializer)
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BackendTrafficPolicy {
	Authorization(Authorization),
	McpAuthorization(McpAuthorization),
	McpAuthentication(McpAuthentication),
	McpGuardrails(Arc<crate::mcp::guardrails::McpGuardrails>),
	SecurityPipeline(LegacySecurityPipeline),
	SecurityAudit(Arc<security_integration_runtime::SecurityConfig>),
	A2a(A2aPolicy),
	#[serde(rename = "http")]
	HTTP(backend::HTTP),
	#[serde(rename = "tcp")]
	TCP(backend::TCP),
	Tunnel(backend::Tunnel),
	#[serde(rename = "backendTLS")]
	BackendTLS(http::backendtls::BackendTLS),
	BackendAuth(BackendAuth),
	InferenceRouting(ext_proc::InferenceRouting),
	#[serde(rename = "ai")]
	AI(Arc<llm::Policy>),
	ExtAuthz(Arc<ext_authz::ExtAuthz>),
	SessionPersistence(http::sessionpersistence::Policy),
	Transformation(Arc<crate::http::transformation_cel::Transformation>),
	Health(health::Policy),

	RequestHeaderModifier(filters::HeaderModifier),
	ResponseHeaderModifier(Arc<filters::HeaderModifier>),
	RequestRedirect(filters::RequestRedirect),
	RequestMirror(Vec<filters::RequestMirror>),
}

#[apply(schema!)]
pub struct A2aPolicy {}

#[apply(schema!)]
pub struct Authorization(pub Arc<RuleSet>);

// Do not use schema! as it will reject the `extra` field
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ResourceMetadata {
	#[serde(flatten)]
	pub extra: BTreeMap<String, Value>,
}

impl ResourceMetadata {
	/// Build RFC-compliant JSON for the protected resource metadata.
	///
	/// - Defaults computed `resource` and `authorization_servers`.
	/// - Converts any additional config keys from camelCase to snake_case.
	/// - Adds MCP-specific fields used by the gateway.
	pub fn to_rfc_json(&self, resource_uri: String, issuer: String) -> Value {
		let mut map = serde_json::Map::new();

		// Computed fields. User can override them if they explicitly configure them.
		map.insert("resource".into(), Value::String(resource_uri));
		map.insert(
			"authorization_servers".into(),
			Value::Array(vec![Value::String(issuer)]),
		);
		// MCP-specific additions
		map.insert(
			"mcp_protocol_version".into(),
			Value::String("2025-06-18".into()),
		);
		map.insert("resource_type".into(), Value::String("mcp-server".into()));

		// Copy user-provided extra keys, converting to snake_case
		for (key, value) in &self.extra {
			let snake = key.to_snake_case();
			map.insert(snake, value.clone());
		}

		Value::Object(map)
	}
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtAuthentication {
	#[serde(flatten)]
	pub jwt: crate::http::jwt::Jwt,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub mcp: Option<McpAuthentication>,
}

impl store::RequestPolicyTrait for JwtAuthentication {
	async fn apply(
		&self,
		_client: &crate::proxy::httpproxy::PolicyClient,
		log: &mut crate::telemetry::log::RequestLog,
		req: &mut crate::http::Request,
	) -> Result<crate::http::PolicyResponse, crate::proxy::ProxyResponse> {
		if !cfg!(feature = "gateway-mcp") && self.mcp.is_some() {
			return Err(
				crate::proxy::ProxyError::ProcessingString(
					"MCP support is not compiled; enable gateway-mcp".into(),
				)
				.into(),
			);
		}
		#[cfg(feature = "gateway-mcp")]
		if let Some(auth) = &self.mcp {
			if !crate::mcp::auth::is_well_known_endpoint(req.uri().path()) {
				self.jwt.apply(Some(log), req).await.map_err(|e| {
					crate::proxy::ProxyResponse::from(crate::mcp::auth::create_auth_required_response(
						crate::proxy::ProxyError::JwtAuthenticationFailure(e),
						req,
						auth,
					))
				})?;
			}

			if let Some(resp) = crate::mcp::auth::handle_mcp_request(req, auth, _client).await? {
				return Err(crate::proxy::ProxyResponse::DirectResponse(Box::new(resp)));
			}
			return Ok(crate::http::PolicyResponse::default());
		}

		self
			.jwt
			.apply(Some(log), req)
			.await
			.map_err(crate::proxy::ProxyError::JwtAuthenticationFailure)
			.map_err(crate::proxy::ProxyResponse::from)?;
		Ok(crate::http::PolicyResponse::default())
	}

	fn expressions(&self) -> impl Iterator<Item = &crate::cel::Expression> {
		self.jwt.expressions()
	}
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpAuthentication {
	pub issuer: String,
	pub audiences: Vec<String>,
	pub provider: Option<McpIDP>,
	pub resource_metadata: ResourceMetadata,
	pub jwt_validator: Arc<crate::http::jwt::Jwt>,
	pub mode: McpAuthenticationMode,
	pub client_id: Option<String>,
}

#[apply(schema_enum!)]
#[derive(Default)]
pub enum McpAuthenticationMode {
	/// A valid token, issued by a configured issuer, must be present.
	/// This is the default option.
	#[default]
	Strict,
	/// If a token exists, validate it.
	/// Warning: this allows requests without a JWT token! Additionally, 401 errors will not be returned,
	/// which will not trigger clients to initiate an oauth flow.
	Optional,
	/// Requests are never rejected. This is useful for usage of claims in later steps (authorization, logging, etc).
	/// Warning: this allows requests without a JWT token! Additionally, 401 errors will not be returned,
	/// which will not trigger clients to initiate an oauth flow.
	Permissive,
}

impl From<McpAuthenticationMode> for crate::http::jwt::Mode {
	fn from(value: McpAuthenticationMode) -> crate::http::jwt::Mode {
		match value {
			McpAuthenticationMode::Strict => crate::http::jwt::Mode::Strict,
			McpAuthenticationMode::Optional => crate::http::jwt::Mode::Optional,
			McpAuthenticationMode::Permissive => crate::http::jwt::Mode::Permissive,
		}
	}
}

// Local configuration for MCP authentication
#[apply(schema_de!)]
pub struct LocalMcpAuthentication {
	/// Expected token issuer, matched against the JWT `iss` claim.
	pub issuer: String,
	/// Accepted token audiences, matched against the JWT `aud` claim.
	pub audiences: Vec<String>,
	/// Identity provider type used to derive MCP authorization metadata and default JWKS URLs.
	pub provider: Option<McpIDP>,
	/// Protected resource metadata returned to MCP clients.
	pub resource_metadata: ResourceMetadata,
	/// JSON Web Key Set used to verify token signatures. Can be inline, from a file, or fetched remotely.
	pub jwks: FileInlineOrRemote,
	/// Controls whether MCP requests must include a valid JWT.
	#[serde(default)]
	pub mode: McpAuthenticationMode,
	/// Where to read the JWT from in incoming MCP requests.
	#[serde(default)]
	pub authorization_location: http::auth::AuthorizationLocation,
	/// Claim requirements to enforce after the token signature is verified.
	#[serde(default)]
	pub jwt_validation_options: http::jwt::JWTValidationOptions,
	/// OAuth client ID advertised to MCP clients when needed.
	pub client_id: Option<String>,
}

impl LocalMcpAuthentication {
	pub fn as_jwt(&self) -> anyhow::Result<http::jwt::LocalJwtConfig> {
		let jwks = match &self.jwks {
			FileInlineOrRemote::Remote { url } => FileInlineOrRemote::Remote {
				url: if !url.to_string().is_empty() {
					url.clone()
				} else {
					match &self.provider {
						None | Some(McpIDP::Auth0 { .. }) | Some(McpIDP::Okta { .. }) => {
							format!("{}/.well-known/jwks.json", self.issuer).parse()?
						},
						Some(McpIDP::Descope {}) => {
							// For agentic issuers (https://api.descope.com/v1/apps/agentic/{project-id}/{server-id}),
							// JWKS lives at the project level: https://api.descope.com/{project-id}/.well-known/jwks.json
							let parsed: url::Url = self.issuer.parse()?;
							let segments: Vec<&str> = parsed.path().trim_start_matches('/').split('/').collect();
							if segments.len() >= 5
								&& segments[0] == "v1"
								&& segments[1] == "apps"
								&& segments[2] == "agentic"
							{
								let project_id = segments[3];
								let base = format!(
									"{}://{}/{}",
									parsed.scheme(),
									parsed.host_str().unwrap_or_default(),
									project_id
								);
								format!("{base}/.well-known/jwks.json").parse()?
							} else {
								format!("{}/.well-known/jwks.json", self.issuer).parse()?
							}
						},
						Some(McpIDP::Keycloak { .. }) => {
							format!("{}/protocol/openid-connect/certs", self.issuer).parse()?
						},
					}
				},
			},
			FileInlineOrRemote::Inline(_) | FileInlineOrRemote::File { .. } => self.jwks.clone(),
		};

		Ok(http::jwt::LocalJwtConfig::Single {
			mode: self.mode.into(),
			location: self.authorization_location.clone(),
			issuer: self.issuer.clone(),
			audiences: Some(self.audiences.clone()),
			jwks,
			jwt_validation_options: self.jwt_validation_options.clone(),
		})
	}

	/// Translate the local (file/env) config into a runtime `McpAuthentication` with a ready validator.
	pub async fn translate(
		&self,
		resources: &crate::resource_manager::ResourceFetcher,
	) -> anyhow::Result<McpAuthentication> {
		let jwt_cfg = self.as_jwt()?;
		let jwt = jwt_cfg.try_into(resources).await?;
		Ok(McpAuthentication {
			issuer: self.issuer.clone(),
			audiences: self.audiences.clone(),
			provider: self.provider.clone(),
			resource_metadata: self.resource_metadata.clone(),
			jwt_validator: Arc::new(jwt),
			mode: self.mode,
			client_id: self.client_id.clone(),
		})
	}
}

#[apply(schema!)]
pub enum McpIDP {
	Auth0 {},
	Keycloak {},
	Okta {},
	Descope {},
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(with = "String"))]
pub enum Target {
	Address(SocketAddr),
	Hostname(Strng, u16),
	/// Unix domain socket path (e.g., "unix:/path/to/socket")
	UnixSocket(PathBuf),
}

impl<'de> serde::Deserialize<'de> for Target {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		serdes::de_parse(deserializer)
	}
}

impl serde::Serialize for Target {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(&self.to_string())
	}
}

impl From<(&str, u16)> for Target {
	fn from((host, port): (&str, u16)) -> Self {
		match host.parse::<IpAddr>() {
			Ok(target) => Target::Address(SocketAddr::new(target, port)),
			Err(_) => Target::Hostname(host.into(), port),
		}
	}
}

impl TryFrom<&str> for Target {
	type Error = anyhow::Error;

	fn try_from(hostport: &str) -> Result<Self, Self::Error> {
		// Check for unix socket prefix
		if let Some(path) = hostport.strip_prefix("unix:") {
			return Ok(Target::UnixSocket(PathBuf::from(path)));
		}
		let Some((host, port)) = hostport.split_once(":") else {
			anyhow::bail!("invalid host:port: {hostport}");
		};
		let port: u16 = port.parse()?;
		Ok((host, port).into())
	}
}

impl Display for Target {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let str = match self {
			Target::Address(addr) => addr.to_string(),
			Target::Hostname(hostname, port) => format!("{hostname}:{port}"),
			Target::UnixSocket(path) => format!("unix:{}", path.display()),
		};
		write!(f, "{str}")
	}
}

impl Target {
	pub fn hostport(&self) -> String {
		match self {
			Target::Address(addr) => addr.to_string(),
			Target::Hostname(hostname, port) => format!("{hostname}:{port}"),
			Target::UnixSocket(path) => path
				.file_name()
				.and_then(|os| os.to_str())
				.unwrap_or_default()
				.to_string(),
		}
	}
}

#[apply(schema!)]
pub struct KeepaliveConfig {
	#[serde(default = "defaults::always_true")]
	pub enabled: bool,
	#[serde(with = "serde_dur")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	#[serde(default = "defaults::keepalive_time")]
	pub time: Duration,
	#[serde(with = "serde_dur")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	#[serde(default = "defaults::keepalive_interval")]
	pub interval: Duration,
	#[serde(default = "defaults::keepalive_retries")]
	pub retries: u32,
}

impl Default for KeepaliveConfig {
	fn default() -> Self {
		KeepaliveConfig {
			enabled: true,
			time: defaults::keepalive_time(),
			interval: defaults::keepalive_interval(),
			retries: defaults::keepalive_retries(),
		}
	}
}

pub mod defaults {
	use std::time::Duration;

	pub fn always_true() -> bool {
		true
	}
	pub fn keepalive_retries() -> u32 {
		9
	}
	pub fn keepalive_interval() -> Duration {
		Duration::from_secs(180)
	}
	pub fn keepalive_time() -> Duration {
		Duration::from_secs(180)
	}
}
