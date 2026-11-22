//! Listener TLS configuration from YAML input to the prepared Rustls server.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use prometheus_client::encoding::EncodeLabelValue;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::pem::{PemObject, SectionKind};
use serde::{Deserialize, Serialize, Serializer};

#[cfg(feature = "schema")]
use crate::JsonSchema;
use crate::control::caclient::CaClient;
use crate::serdes::{apply, schema_de, schema_enum};
use crate::transport::tls;

use super::{dynamic_ca_cert, frontend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EncodeLabelValue)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[allow(non_camel_case_types)]
pub enum TLSVersion {
	TLS_V1_0,
	TLS_V1_1,
	TLS_V1_2,
	TLS_V1_3,
}

#[derive(Default)]
#[apply(schema_de!)]
pub struct LocalTLSServerConfig {
	/// Certificate source mode. Static mode uses cert/key as the leaf certificate; dynamic CA
	/// mode uses cert/key as a CA for on-demand SNI leaf certificate issuance.
	#[serde(default)]
	pub mode: LocalTLSServerMode,
	pub cert: PathBuf,
	pub key: PathBuf,
	pub root: Option<PathBuf>,
	/// Optional cipher suite allowlist (order is preserved).
	#[cfg_attr(feature = "schema", schemars(with = "Option<Vec<String>>"))]
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cipher_suites: Option<Vec<crate::transport::tls::CipherSuite>>,
	/// Minimum supported TLS version (only TLS 1.2 and 1.3 are supported).
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		rename = "minTLSVersion",
		alias = "minTlsVersion"
	)]
	pub min_tls_version: Option<TLSVersion>,
	/// Maximum supported TLS version (only TLS 1.2 and 1.3 are supported).
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		rename = "maxTLSVersion",
		alias = "maxTlsVersion"
	)]
	pub max_tls_version: Option<TLSVersion>,
	/// Key exchange groups allowed for negotiating TLS.
	#[cfg_attr(feature = "schema", schemars(with = "Option<Vec<String>>"))]
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub key_exchange_groups: Option<Vec<crate::transport::tls::KeyExchangeGroup>>,
}

#[apply(schema_enum!)]
#[derive(Default)]
pub enum LocalTLSServerMode {
	#[default]
	Static,
	DynamicCa,
}

impl LocalTLSServerConfig {
	pub(super) async fn into_server_tls_config_with_resources(
		self,
		dynamic_ca_cert_cache: crate::DynamicCaCertCacheConfig,
		resources: &crate::resource_manager::ResourceFetcher,
	) -> anyhow::Result<ServerTLSConfig> {
		let cert_pem = resources
			.fetch(crate::resource_manager::ResourceRef::File(self.cert))
			.await?
			.to_vec();
		let key_pem = resources
			.fetch(crate::resource_manager::ResourceRef::File(self.key))
			.await?
			.to_vec();
		let root_pem = match self.root {
			Some(root) => Some(
				resources
					.fetch(crate::resource_manager::ResourceRef::File(root))
					.await?
					.to_vec(),
			),
			None => None,
		};
		match self.mode {
			LocalTLSServerMode::Static => ServerTLSConfig::from_pem_with_profile(
				cert_pem,
				key_pem,
				root_pem,
				vec![b"h2".to_vec(), b"http/1.1".to_vec()],
				self.min_tls_version,
				self.max_tls_version,
				self.cipher_suites,
				self.key_exchange_groups,
				false,
			),
			LocalTLSServerMode::DynamicCa => {
				if root_pem.is_some() {
					anyhow::bail!("tls.root is not supported with tls.mode=dynamicCa")
				}
				ServerTLSConfig::dynamic_ca_with_profile(
					cert_pem,
					key_pem,
					vec![b"h2".to_vec(), b"http/1.1".to_vec()],
					self.min_tls_version,
					self.max_tls_version,
					self.cipher_suites,
					self.key_exchange_groups,
					dynamic_ca_cert_cache,
				)
			},
		}
	}
}

type Alpns = Vec<Vec<u8>>;

#[derive(Debug, Clone, Eq, PartialEq)]
struct ServerTlsInputs {
	cert_pem: Vec<u8>,
	key_pem: Vec<u8>,
	// If present, require and verify client certificates using these roots.
	root_pem: Option<Vec<u8>>,
	// If true, request client certs but allow absent or invalid certs as insecure fallback.
	allow_insecure_mtls: bool,
	// Default ALPNs configured at creation time.
	default_alpns: Alpns,
	// Default cipher suites configured at creation time.
	default_cipher_suites: Vec<crate::transport::tls::CipherSuite>,
	// Default key exchange groups configured at creation time.
	default_key_exchange_groups: Vec<crate::transport::tls::KeyExchangeGroup>,
	dynamic_ca_cert_cache: crate::DynamicCaCertCacheConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ServerTlsProfileKey {
	alpns: Alpns,
	min_version: Option<TLSVersion>,
	max_version: Option<TLSVersion>,
	// Order-sensitive: we intentionally preserve user-provided cipher suite ordering.
	cipher_suites: Vec<crate::transport::tls::CipherSuite>,
	key_exchange_groups: Vec<crate::transport::tls::KeyExchangeGroup>,
}

impl frontend::TLS {
	/// Fast path: no overrides
	fn is_fast_path(&self) -> bool {
		// empty list is the same as no overrides
		let no_cipher_suite_override = self
			.cipher_suites
			.as_deref()
			.is_none_or(|suites| suites.is_empty());

		self.alpn.is_none()
			&& self.min_version.is_none()
			&& self.max_version.is_none()
			&& self
				.key_exchange_groups
				.as_deref()
				.is_none_or(|groups| groups.is_empty())
			&& no_cipher_suite_override
	}

	fn server_tls_profile_key(&self, inputs: &ServerTlsInputs) -> ServerTlsProfileKey {
		let alpns = self
			.alpn
			.clone()
			.unwrap_or_else(|| inputs.default_alpns.clone());
		let cipher_suites = self
			.cipher_suites
			.clone()
			.filter(|suites| !suites.is_empty())
			.unwrap_or_else(|| inputs.default_cipher_suites.clone());
		let key_exchange_groups = self
			.key_exchange_groups
			.clone()
			.filter(|groups| !groups.is_empty())
			.unwrap_or_else(|| inputs.default_key_exchange_groups.clone());
		ServerTlsProfileKey {
			alpns,
			min_version: self.min_version,
			max_version: self.max_version,
			cipher_suites,
			key_exchange_groups,
		}
	}
}

#[derive(Debug, Clone)]
pub struct ServerTLSConfig {
	source: ServerTlsCertificateSource,
	/// Cached base config (built from `inputs` using defaults). Kept for fast path when no overrides
	/// are requested.
	base_config: Option<Arc<ServerConfig>>,
	/// Original inputs required to rebuild a fresh `ServerConfig` for a given profile.
	inputs: Option<Arc<ServerTlsInputs>>,
	/// Original strict verifier used when ALLOW_INSECURE_FALLBACK is enabled.
	insecure_fallback_verifier: Option<Arc<dyn ClientCertVerifier>>,
	per_profile_config: Arc<RwLock<HashMap<ServerTlsProfileKey, Arc<ServerConfig>>>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ServerTlsCertificateSource {
	Static,
	DynamicCa,
	IstioWorkload { mtls: bool, default_alpns: Alpns },
}

impl Eq for ServerTLSConfig {}
impl PartialEq for ServerTLSConfig {
	fn eq(&self, other: &Self) -> bool {
		self.source == other.source && self.inputs == other.inputs
	}
}

impl ServerTLSConfig {
	pub fn new(config: Arc<ServerConfig>) -> Self {
		Self {
			source: ServerTlsCertificateSource::Static,
			base_config: Some(config),
			inputs: None,
			insecure_fallback_verifier: None,
			per_profile_config: Arc::new(Default::default()),
		}
	}

	pub fn from_pem(
		cert_pem: Vec<u8>,
		key_pem: Vec<u8>,
		root_pem: Option<Vec<u8>>,
		default_alpns: Alpns,
	) -> anyhow::Result<Self> {
		Self::from_pem_with_profile(
			cert_pem,
			key_pem,
			root_pem,
			default_alpns,
			None,
			None,
			None,
			None,
			false,
		)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn from_pem_with_profile(
		cert_pem: Vec<u8>,
		key_pem: Vec<u8>,
		root_pem: Option<Vec<u8>>,
		default_alpns: Alpns,
		min_version: Option<TLSVersion>,
		max_version: Option<TLSVersion>,
		cipher_suites: Option<Vec<crate::transport::tls::CipherSuite>>,
		key_exchange_groups: Option<Vec<crate::transport::tls::KeyExchangeGroup>>,
		allow_insecure_mtls: bool,
	) -> anyhow::Result<Self> {
		let inputs = Arc::new(ServerTlsInputs {
			cert_pem,
			key_pem,
			root_pem,
			allow_insecure_mtls,
			default_alpns,
			default_cipher_suites: cipher_suites.clone().unwrap_or_default(),
			default_key_exchange_groups: key_exchange_groups.clone().unwrap_or_default(),
			dynamic_ca_cert_cache: Default::default(),
		});
		let suites = cipher_suites.as_deref().filter(|s| !s.is_empty());
		let groups = key_exchange_groups.as_deref().filter(|g| !g.is_empty());
		let (base, insecure_fallback_verifier) = Self::build_server_config(
			&inputs,
			None,
			min_version,
			max_version,
			suites.unwrap_or(&[]),
			groups.unwrap_or(&[]),
		)?;
		Ok(Self {
			source: ServerTlsCertificateSource::Static,
			base_config: Some(Arc::new(base)),
			inputs: Some(inputs),
			insecure_fallback_verifier,
			per_profile_config: Arc::new(Default::default()),
		})
	}

	#[allow(clippy::too_many_arguments)]
	fn dynamic_ca_with_profile(
		ca_cert_pem: Vec<u8>,
		ca_key_pem: Vec<u8>,
		default_alpns: Vec<Vec<u8>>,
		min_version: Option<TLSVersion>,
		max_version: Option<TLSVersion>,
		cipher_suites: Option<Vec<crate::transport::tls::CipherSuite>>,
		key_exchange_groups: Option<Vec<crate::transport::tls::KeyExchangeGroup>>,
		dynamic_ca_cert_cache: crate::DynamicCaCertCacheConfig,
	) -> anyhow::Result<Self> {
		let inputs = Arc::new(ServerTlsInputs {
			cert_pem: ca_cert_pem,
			key_pem: ca_key_pem,
			root_pem: None,
			allow_insecure_mtls: false,
			default_alpns,
			default_cipher_suites: cipher_suites.clone().unwrap_or_default(),
			default_key_exchange_groups: key_exchange_groups.clone().unwrap_or_default(),
			dynamic_ca_cert_cache,
		});
		let suites = cipher_suites.as_deref().filter(|s| !s.is_empty());
		let groups = key_exchange_groups.as_deref().filter(|g| !g.is_empty());
		let base = dynamic_ca_cert::build_dynamic_ca_server_config(
			&inputs.cert_pem,
			&inputs.key_pem,
			None,
			&inputs.default_alpns,
			min_version,
			max_version,
			suites.unwrap_or(&[]),
			groups.unwrap_or(&[]),
			&inputs.dynamic_ca_cert_cache,
		)?;
		Ok(Self {
			source: ServerTlsCertificateSource::DynamicCa,
			base_config: Some(Arc::new(base)),
			inputs: Some(inputs),
			insecure_fallback_verifier: None,
			per_profile_config: Arc::new(Default::default()),
		})
	}

	/// new_invalid returns a ServerTLSConfig that always rejects connections
	pub fn new_invalid() -> Self {
		Self {
			source: ServerTlsCertificateSource::Static,
			base_config: None,
			inputs: None,
			insecure_fallback_verifier: None,
			per_profile_config: Arc::new(Default::default()),
		}
	}

	pub fn istio_workload(mtls: bool, default_alpns: Alpns) -> Self {
		Self {
			source: ServerTlsCertificateSource::IstioWorkload {
				mtls,
				default_alpns,
			},
			base_config: None,
			inputs: None,
			insecure_fallback_verifier: None,
			per_profile_config: Arc::new(Default::default()),
		}
	}

	/// config_for returns the appropriate config for the requested ALPN
	/// If none is return, it means the certificates were invalid.
	pub async fn config_for(
		&self,
		tls: Option<&frontend::TLS>,
		ca: Option<&Arc<CaClient>>,
	) -> anyhow::Result<Arc<ServerConfig>> {
		if let ServerTlsCertificateSource::IstioWorkload {
			mtls,
			default_alpns,
		} = &self.source
		{
			let ca = ca.ok_or_else(|| anyhow!("CA is required for Istio workload TLS"))?;
			let alpns = tls
				.and_then(|t| t.alpn.clone())
				.unwrap_or_else(|| default_alpns.clone());
			let cert = ca.get_identity().await?;
			return Ok(Arc::new(cert.server_config(alpns, *mtls)?));
		}

		let inputs = match self.inputs.as_ref() {
			Some(i) => Arc::clone(i),
			None => {
				return self
					.base_config
					.clone()
					.ok_or_else(|| anyhow!("TLS config invalid"));
			},
		};

		// Fast path: no overrides
		if tls.is_none_or(|t| t.is_fast_path())
			&& let Some(c) = self.base_config.clone()
		{
			return Ok(c);
		}

		let key = match tls {
			Some(tls) => tls.server_tls_profile_key(&inputs),
			None => ServerTlsProfileKey {
				alpns: inputs.default_alpns.clone(),
				min_version: None,
				max_version: None,
				cipher_suites: inputs.default_cipher_suites.clone(),
				key_exchange_groups: inputs.default_key_exchange_groups.clone(),
			},
		};

		{
			let reader = self.per_profile_config.read().unwrap();
			if let Some(cached_config) = reader.get(&key) {
				return Ok(Arc::clone(cached_config));
			}
		}
		let mut writer = self.per_profile_config.write().unwrap();
		if let Some(cached_config) = writer.get(&key) {
			return Ok(Arc::clone(cached_config));
		}

		let base = match self.source {
			ServerTlsCertificateSource::Static => {
				let (base, _insecure_fallback_verifier) = Self::build_server_config(
					&inputs,
					Some(&key.alpns),
					key.min_version,
					key.max_version,
					&key.cipher_suites,
					&key.key_exchange_groups,
				)?;
				base
			},
			ServerTlsCertificateSource::DynamicCa => dynamic_ca_cert::build_dynamic_ca_server_config(
				&inputs.cert_pem,
				&inputs.key_pem,
				Some(&key.alpns),
				&inputs.default_alpns,
				key.min_version,
				key.max_version,
				&key.cipher_suites,
				&key.key_exchange_groups,
				&inputs.dynamic_ca_cert_cache,
			)?,
			ServerTlsCertificateSource::IstioWorkload { .. } => unreachable!(),
		};
		let base = Arc::new(base);
		writer.insert(key.clone(), Arc::clone(&base));
		Ok(base)
	}

	pub fn allow_insecure_mtls(&self) -> bool {
		if matches!(
			self.source,
			ServerTlsCertificateSource::IstioWorkload { mtls: true, .. }
		) {
			return false;
		}
		self
			.inputs
			.as_ref()
			.is_some_and(|inputs| inputs.allow_insecure_mtls)
	}

	pub fn include_src_identity_for_connection(&self, conn: &rustls::ServerConnection) -> bool {
		if matches!(
			self.source,
			ServerTlsCertificateSource::IstioWorkload { mtls: true, .. }
		) {
			return true;
		}
		if !self.allow_insecure_mtls() {
			return true;
		}

		let Some(peer_certs) = conn.peer_certificates() else {
			return false;
		};
		let Some((end_entity, intermediates)) = peer_certs.split_first() else {
			return false;
		};

		let Some(verifier) = self.insecure_fallback_verifier.as_ref() else {
			return false;
		};

		let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
			Ok(duration) => rustls::pki_types::UnixTime::since_unix_epoch(duration),
			Err(_) => return false,
		};

		verifier
			.verify_client_cert(end_entity, intermediates, now)
			.is_ok()
	}

	fn build_server_config(
		inputs: &ServerTlsInputs,
		alpns: Option<&[Vec<u8>]>,
		min_version: Option<TLSVersion>,
		max_version: Option<TLSVersion>,
		cipher_suites: &[crate::transport::tls::CipherSuite],
		key_exchange_groups: &[crate::transport::tls::KeyExchangeGroup],
	) -> anyhow::Result<(ServerConfig, Option<Arc<dyn ClientCertVerifier>>)> {
		let provider = crate::transport::tls::provider_with_options(cipher_suites, key_exchange_groups);

		let versions = tls_versions_for_range(min_version, max_version)?;
		let scb = ServerConfig::builder_with_provider(provider.clone())
			.with_protocol_versions(&versions)
			.expect("server config must be valid");

		let mut insecure_fallback_verifier = None;

		let scb = if let Some(root) = &inputs.root_pem {
			let mut roots_store = rustls::RootCertStore::empty();
			let certs = CertificateDer::pem_slice_iter(root).collect::<Result<Vec<_>, _>>()?;
			roots_store.add_parsable_certificates(certs);
			let verify = rustls::server::WebPkiClientVerifier::builder_with_provider(
				Arc::new(roots_store),
				provider,
			)
			.build()?;
			let verify: Arc<dyn ClientCertVerifier> = if inputs.allow_insecure_mtls {
				insecure_fallback_verifier = Some(verify.clone());
				tls::insecure::AllowInsecureMtlsVerifier::new(verify)
			} else {
				verify
			};
			scb.with_client_cert_verifier(verify)
		} else {
			scb.with_no_client_auth()
		};

		let cert_chain = parse_cert(&inputs.cert_pem)?;
		let private_key = parse_key(&inputs.key_pem)?;
		let mut sc = scb.with_single_cert(cert_chain, private_key)?;
		sc.key_log = crate::transport::tls::key_log();
		sc.alpn_protocols = alpns
			.map(|a| a.to_vec())
			.unwrap_or_else(|| inputs.default_alpns.clone());
		Ok((sc, insecure_fallback_verifier))
	}
}

pub(super) fn tls_versions_for_range(
	min_version: Option<TLSVersion>,
	max_version: Option<TLSVersion>,
) -> anyhow::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
	// rustls currently supports TLS1.2 and TLS1.3 in this repo (see `transport::tls::ALL_TLS_VERSIONS`).
	// If older versions are requested, reject early.
	fn ord(v: TLSVersion) -> anyhow::Result<u8> {
		match v {
			TLSVersion::TLS_V1_2 => Ok(12),
			TLSVersion::TLS_V1_3 => Ok(13),
			_ => Err(anyhow!("unsupported TLS version: {v:?}")),
		}
	}

	let min = min_version.map(ord).transpose()?;
	let max = max_version.map(ord).transpose()?;
	if let (Some(min), Some(max)) = (min, max)
		&& min > max
	{
		return Err(anyhow!("invalid TLS version range"));
	}

	let min = min.unwrap_or(12);
	let max = max.unwrap_or(13);

	let mut out = Vec::new();
	if min <= 12 && max >= 12 {
		out.push(&rustls::version::TLS12);
	}
	if min <= 13 && max >= 13 {
		out.push(&rustls::version::TLS13);
	}
	if out.is_empty() {
		return Err(anyhow!("invalid TLS version range"));
	}
	Ok(out)
}

impl serde::Serialize for ServerTLSConfig {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		// TODO: store raw pem
		serializer.serialize_none()
	}
}

#[cfg(feature = "schema")]
impl JsonSchema for ServerTLSConfig {
	fn schema_name() -> std::borrow::Cow<'static, str> {
		"ServerTLSConfig".into()
	}

	fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
		schemars::json_schema!({ "type": "null" })
	}
}

pub fn parse_cert(cert: &[u8]) -> Result<Vec<CertificateDer<'static>>, anyhow::Error> {
	let parsed = <(SectionKind, Vec<u8>)>::pem_slice_iter(cert).collect::<Result<Vec<_>, _>>()?;
	if parsed.is_empty() {
		return Err(anyhow!("no certificate"));
	}

	parsed
		.into_iter()
		.map(|(kind, der)| {
			if kind != SectionKind::Certificate {
				return Err(anyhow!("no certificate"));
			}
			Ok(CertificateDer::from(der))
		})
		.collect()
}

pub fn parse_key(key: &[u8]) -> Result<PrivateKeyDer<'static>, anyhow::Error> {
	let (kind, der) = <(SectionKind, Vec<u8>)>::from_pem_slice(key).map_err(|e| match e {
		rustls_pki_types::pem::Error::NoItemsFound => anyhow!("no key"),
		_ => anyhow!(e),
	})?;
	match kind {
		SectionKind::PrivateKey => Ok(PrivateKeyDer::Pkcs8(der.into())),
		SectionKind::RsaPrivateKey => Ok(PrivateKeyDer::Pkcs1(der.into())),
		SectionKind::EcPrivateKey => Ok(PrivateKeyDer::Sec1(der.into())),
		_ => Err(anyhow!("unsupported key")),
	}
}
