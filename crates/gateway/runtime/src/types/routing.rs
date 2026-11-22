//! Runtime routes, match rules, and their listener and hostname indexes.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::num::NonZeroU16;
use std::sync::Arc;

use hashbrown::Equivalent;
use platform_core::prelude::{Strng, strng, trace};
use serde::{Serialize, Serializer};

#[cfg(feature = "schema")]
use crate::JsonSchema;
use crate::http::{HeaderOrPseudo, HeaderValue};
use crate::serdes::{apply, de_parse, schema, schema_ser_schema, ser_bytes, ser_display};

use super::agent::{
	BackendKey, BackendReference, BackendTrafficPolicy, BackendWithPolicies, Listener, ListenerKey,
	ListenerProtocol, PolicyTargetRef, SimpleBackendReference, SimpleBackendWithPolicies,
	TrafficPolicy,
};
use super::discovery::NamespacedHostname;

pub(super) fn default_weight() -> usize {
	1
}

#[apply(schema_ser_schema!)]
pub struct Route {
	// Internal name
	pub key: RouteKey,
	/// Service this route targets (set when parentRef is a Service).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub service_key: Option<crate::types::discovery::NamespacedHostname>,
	/// Port of the targeted service this route is scoped to. Zero matches any port.
	#[serde(default, skip_serializing_if = "crate::serdes::is_default")]
	pub service_port: u16,
	#[serde(flatten)]
	// User facing name of the route
	pub name: RouteName,
	/// Can be a wildcard
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub hostnames: Vec<Strng>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub matches: Vec<RouteMatch>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub backends: Vec<RouteBackendReference>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[cfg_attr(feature = "schema", schemars(with = "Vec<serde_json::Value>"))]
	pub inline_policies: Vec<TrafficPolicy>,
}

pub type RouteKey = Strng;
pub type RouteGroupKey = Strng;
pub type RouteRuleName = Strng;

#[apply(schema!)]
#[derive(Hash, Eq, PartialEq)]
pub struct RouteName {
	pub name: Strng,
	pub namespace: Strng,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rule_name: Option<Strng>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub kind: Option<Strng>,
}

impl RouteName {
	pub fn as_route_name(&self) -> Strng {
		strng::format!("{}/{}", self.namespace, self.name)
	}
	pub fn as_route_target_ref(&self) -> PolicyTargetRef {
		PolicyTargetRef::Route {
			name: self.name.as_ref(),
			namespace: self.namespace.as_ref(),
			rule_name: None,
			kind: self.kind.as_deref(),
		}
	}
	pub fn as_route_rule_target_ref(&self) -> PolicyTargetRef {
		PolicyTargetRef::Route {
			name: self.name.as_ref(),
			namespace: self.namespace.as_ref(),
			rule_name: self.rule_name.as_deref(),
			kind: self.kind.as_deref(),
		}
	}
}

#[apply(schema_ser_schema!)]
pub struct TCPRoute {
	// Internal name
	pub key: RouteKey,
	/// Service this route targets (set when parentRef is a Service).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub service_key: Option<crate::types::discovery::NamespacedHostname>,
	/// Port of the targeted service this route is scoped to. Zero matches any port.
	#[serde(default, skip_serializing_if = "crate::serdes::is_default")]
	pub service_port: u16,
	// User facing name of the route
	#[serde(flatten)]
	pub name: RouteName,
	// Can be a wildcard. Not applicable for TCP, only for TLS
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub hostnames: Vec<Strng>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub backends: Vec<TCPRouteBackendReference>,
}

#[apply(schema_ser_schema!)]
pub struct TCPRouteBackendReference {
	#[serde(default = "default_weight")]
	pub weight: usize,
	pub backend: SimpleBackendReference,
	// Inline policies ("filters") of the route backend
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[cfg_attr(feature = "schema", schemars(with = "Vec<serde_json::Value>"))]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TCPRouteBackend {
	#[serde(default = "default_weight")]
	pub weight: usize,
	pub backend: SimpleBackendWithPolicies,
	// Inline policies ("filters") of the route backend
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

#[apply(schema!)]
pub struct RouteMatch {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub headers: Vec<HeaderMatch>,
	#[serde(default = "default_route_match_path")]
	pub path: PathMatch,
	#[serde(default, flatten, skip_serializing_if = "Option::is_none")]
	pub method: Option<MethodMatch>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub query: Vec<QueryMatch>,
}

fn default_route_match_path() -> PathMatch {
	PathMatch::PathPrefix("/".into())
}

#[apply(schema!)]
pub struct MethodMatch {
	pub method: Strng,
}

#[apply(schema!)]
pub struct HeaderMatch {
	#[serde(serialize_with = "ser_display", deserialize_with = "de_parse")]
	#[cfg_attr(feature = "schema", schemars(with = "String"))]
	pub name: HeaderOrPseudo,
	pub value: HeaderValueMatch,
}

#[apply(schema!)]
pub struct QueryMatch {
	#[serde(serialize_with = "ser_display")]
	pub name: Strng,
	pub value: QueryValueMatch,
}

#[apply(schema!)]
pub enum QueryValueMatch {
	Exact(Strng),
	Regex(
		#[serde(with = "serde_regex")]
		#[cfg_attr(feature = "schema", schemars(with = "String"))]
		regex::Regex,
	),
	Invalid,
}

#[apply(schema!)]
pub enum HeaderValueMatch {
	Exact(
		#[serde(serialize_with = "ser_bytes", deserialize_with = "de_parse")]
		#[cfg_attr(feature = "schema", schemars(with = "String"))]
		HeaderValue,
	),
	Regex(
		#[serde(with = "serde_regex")]
		#[cfg_attr(feature = "schema", schemars(with = "String"))]
		regex::Regex,
	),
	Invalid,
}

#[apply(schema!)]
pub enum PathMatch {
	Exact(Strng),
	PathPrefix(Strng),
	Regex(
		#[serde(with = "serde_regex")]
		#[cfg_attr(feature = "schema", schemars(with = "String"))]
		regex::Regex,
	),
	Invalid,
}

#[apply(schema!)]
#[derive(Eq, PartialEq)]
pub enum HostRedirect {
	/// Replace the full authority, including host and optional port.
	Full(Strng),
	/// Replace only the host and preserve the effective port.
	Host(Strng),
	/// Replace only the port.
	Port(NonZeroU16),
	/// Use the selected backend host when possible.
	Auto,
	/// Leave the authority unchanged.
	None,
}

#[apply(schema!)]
#[derive(Eq, PartialEq, Copy)]
pub enum HostRedirectOverride {
	/// Use the selected backend host when possible.
	Auto,
	/// Leave the authority unchanged.
	None,
}

#[apply(schema!)]
#[derive(Eq, PartialEq)]
pub enum PathRedirect {
	/// Replace the full request path.
	Full(Strng),
	/// Replace only the matched path prefix.
	Prefix(Strng),
}

#[apply(schema_ser_schema!)]
pub enum RouteBackendTarget {
	Service { name: NamespacedHostname, port: u16 },
	Backend(BackendKey),
	RouteGroup(RouteGroupKey),
	Invalid,
}

impl From<BackendReference> for RouteBackendTarget {
	fn from(value: BackendReference) -> Self {
		match value {
			BackendReference::Service { name, port } => Self::Service { name, port },
			BackendReference::Backend(key) => Self::Backend(key),
			BackendReference::Invalid => Self::Invalid,
		}
	}
}

impl RouteBackendTarget {
	pub fn as_backend_reference(&self) -> Option<BackendReference> {
		match self {
			Self::Service { name, port } => Some(BackendReference::Service {
				name: name.clone(),
				port: *port,
			}),
			Self::Backend(key) => Some(BackendReference::Backend(key.clone())),
			Self::Invalid => Some(BackendReference::Invalid),
			Self::RouteGroup(_) => None,
		}
	}
}

#[apply(schema_ser_schema!)]
pub struct RouteBackendReference {
	#[serde(default = "default_weight")]
	pub weight: usize,
	#[serde(flatten)]
	pub target: RouteBackendTarget,
	// Inline policies ("filters") of the route backend
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[cfg_attr(feature = "schema", schemars(with = "Vec<serde_json::Value>"))]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteBackend {
	#[serde(default = "default_weight")]
	pub weight: usize,
	pub backend: BackendWithPolicies,
	// Inline policies ("filters") of the route backend
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inline_policies: Vec<BackendTrafficPolicy>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(
	feature = "schema",
	schemars(with = "std::collections::HashMap<ListenerKey, Arc<Listener>>")
)]
pub struct ListenerSet {
	pub inner: HashMap<ListenerKey, Arc<Listener>>,
}

impl serde::Serialize for ListenerSet {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.inner.serialize(serializer)
	}
}

impl ListenerSet {
	pub fn from_list<const N: usize>(l: [Listener; N]) -> ListenerSet {
		let mut listeners = HashMap::with_capacity(l.len());
		for ls in l.into_iter() {
			listeners.insert(ls.key.clone(), Arc::new(ls));
		}
		ListenerSet { inner: listeners }
	}

	pub fn best_match(&self, host: &str) -> Option<Arc<Listener>> {
		self.best_match_filtered(host, |_| true)
	}

	/// Match only listeners with HTTP protocol (no TLS).
	pub fn best_match_http(&self, host: &str) -> Option<Arc<Listener>> {
		self.best_match_filtered(host, |p| matches!(p, ListenerProtocol::HTTP))
	}

	/// Match only listeners with TLS-capable protocol (HTTPS or TLS).
	pub fn best_match_tls(&self, host: &str) -> Option<Arc<Listener>> {
		self.best_match_filtered(host, |p| {
			matches!(p, ListenerProtocol::HTTPS(_) | ListenerProtocol::TLS(_))
		})
	}

	fn best_match_filtered(
		&self,
		host: &str,
		filter: impl Fn(&ListenerProtocol) -> bool,
	) -> Option<Arc<Listener>> {
		if let Some(best) = self
			.inner
			.values()
			.filter(|l| filter(&l.protocol))
			.find(|l| l.hostname == host)
		{
			trace!("found best match for {host} (exact)");
			return Some(best.clone());
		}
		if let Some(best) = self
			.inner
			.values()
			.filter(|l| {
				filter(&l.protocol)
					&& l.hostname.starts_with("*")
					&& host.ends_with(&l.hostname.as_str()[1..])
			})
			.max_by_key(|l| l.hostname.len())
		{
			trace!("found best match for {host} (wildcard {})", best.hostname);
			return Some(best.clone());
		}
		trace!("trying to find best match for {host} (empty hostname)");
		self
			.inner
			.values()
			.filter(|l| filter(&l.protocol))
			.find(|l| l.hostname.is_empty())
			.cloned()
	}

	pub fn insert(&mut self, v: Listener) {
		self.inner.insert(v.key.clone(), Arc::new(v));
	}

	pub fn contains(&self, key: &ListenerKey) -> bool {
		self.inner.contains_key(key)
	}

	pub fn get(&self, key: &ListenerKey) -> Option<&Listener> {
		self.inner.get(key).map(Arc::as_ref)
	}

	pub fn get_exactly_one(&self) -> anyhow::Result<Arc<Listener>> {
		if self.inner.len() != 1 {
			anyhow::bail!("expecting only one listener for TCP");
		}
		self
			.inner
			.iter()
			.next()
			.ok_or_else(|| anyhow::anyhow!("expecting one listener"))
			.map(|(_k, v)| v.clone())
	}

	pub fn remove(&mut self, key: &ListenerKey) -> Option<Arc<Listener>> {
		self.inner.remove(key)
	}

	pub fn iter(&self) -> impl Iterator<Item = &Listener> {
		self.inner.values().map(Arc::as_ref)
	}
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize)]
pub enum HostnameMatch {
	Exact(Strng),
	// *.example.com -> Wildcard(example.com)
	Wildcard(Strng),
	None,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize)]
pub enum HostnameMatchRef<'a> {
	Exact(&'a str),
	// *.example.com -> Wildcard(example.com)
	Wildcard(&'a str),
	None,
}
impl Equivalent<HostnameMatch> for HostnameMatchRef<'_> {
	fn equivalent(&self, key: &HostnameMatch) -> bool {
		self == &HostnameMatchRef::from(key)
	}
}

impl<'a> From<&'a HostnameMatch> for HostnameMatchRef<'a> {
	fn from(value: &'a HostnameMatch) -> Self {
		match value {
			HostnameMatch::Exact(e) => HostnameMatchRef::Exact(e.as_str()),
			HostnameMatch::Wildcard(w) => HostnameMatchRef::Wildcard(w.as_str()),
			HostnameMatch::None => HostnameMatchRef::None,
		}
	}
}

impl From<Strng> for HostnameMatch {
	fn from(s: Strng) -> Self {
		if let Some(s) = s.strip_prefix("*.") {
			HostnameMatch::Wildcard(strng::new(s))
		} else {
			HostnameMatch::Exact(s.clone())
		}
	}
}

impl HostnameMatch {
	pub fn all_matches_or_none<'a>(
		hostname: Option<&'a str>,
	) -> Box<dyn Iterator<Item = HostnameMatchRef<'a>> + '_> {
		match hostname {
			None => Box::new(std::iter::once(HostnameMatchRef::None)),
			Some(h) => Box::new(Self::all_matches(h)),
		}
	}
	pub fn all_matches<'a>(hostname: &'a str) -> impl Iterator<Item = HostnameMatchRef<'a>> + '_ {
		Self::all_actual_matches(hostname).chain(std::iter::once(HostnameMatchRef::None))
	}
	fn all_actual_matches<'a>(hostname: &'a str) -> impl Iterator<Item = HostnameMatchRef<'a>> + '_ {
		let has_wildcard_prefix = hostname.starts_with("*.");

		let exact_match = if has_wildcard_prefix {
			None
		} else {
			Some(HostnameMatchRef::Exact(hostname))
		};

		let wildcards = hostname.char_indices().filter_map(move |(i, c)| {
			if c == '.' {
				Some(HostnameMatchRef::Wildcard(&hostname[i + 1..]))
			} else {
				None
			}
		});

		exact_match.into_iter().chain(wildcards)
	}
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize)]
pub struct SingleRouteMatch {
	key: RouteKey,
	index: usize,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(
	feature = "schema",
	schemars(with = "std::collections::HashMap<RouteKey, Arc<Route>>")
)]
pub struct RouteSet {
	// Hostname -> []routes, sorted so that route matching can do a linear traversal
	inner: hashbrown::HashMap<HostnameMatch, Vec<SingleRouteMatch>>,
	// All routes
	all: HashMap<RouteKey, Arc<Route>>,
}

impl serde::Serialize for RouteSet {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.all.serialize(serializer)
	}
}

impl RouteSet {
	pub fn from_list(l: Vec<Route>) -> RouteSet {
		let mut rs = RouteSet::default();
		for ls in l.into_iter() {
			rs.insert(ls);
		}
		rs
	}

	pub fn get_hostname(
		&self,
		hnm: &HostnameMatchRef,
	) -> impl Iterator<Item = (Arc<Route>, &RouteMatch)> {
		self.inner.get(hnm).into_iter().flatten().flat_map(|rl| {
			self
				.all
				.get(&rl.key)
				.map(|r| (r.clone(), r.matches.get(rl.index).expect("corrupted state")))
		})
	}

	pub fn get_by_name(&self, name: &RouteName) -> Option<Arc<Route>> {
		self.all.values().find(|route| route.name == *name).cloned()
	}

	pub fn insert(&mut self, r: Route) {
		if self.all.contains_key(&r.key) {
			self.remove(&r.key);
		}
		let r = Arc::new(r);
		// Insert the route into all HashMap first so it's available during binary search
		self.all.insert(r.key.clone(), r.clone());

		for hostname_match in Self::hostname_matchers(&r) {
			let v = self.inner.entry(hostname_match).or_default();
			for (idx, m) in r.matches.iter().enumerate() {
				let to_insert = v.binary_search_by(|existing| {
					let have = self.all.get(&existing.key).expect("corrupted state");
					let have_match = have.matches.get(existing.index).expect("corrupted state");

					Ordering::reverse(Self::compare_route(
						(m, &r.key),
						(have_match, &existing.key),
					))
				});
				let insert_idx = to_insert.unwrap_or_else(|pos| pos);
				v.insert(
					insert_idx,
					SingleRouteMatch {
						key: r.key.clone(),
						index: idx,
					},
				);
			}
		}
	}

	fn compare_route(a: (&RouteMatch, &RouteKey), b: (&RouteMatch, &RouteKey)) -> Ordering {
		let (a, a_key) = a;
		let (b, b_key) = b;
		// Compare RouteMatch according to Gateway API sorting requirements
		// 1. Path match type (Exact > PathPrefix > Regex)
		let path_rank1 = get_path_rank(&a.path);
		let path_rank2 = get_path_rank(&b.path);
		if path_rank1 != path_rank2 {
			return Ordering::reverse(path_rank1.cmp(&path_rank2));
		}
		// 2. Path length (longer paths first)
		let path_len1 = get_path_length(&a.path);
		let path_len2 = get_path_length(&b.path);
		if path_len1 != path_len2 {
			return Ordering::reverse(path_len1.cmp(&path_len2)); // Reverse order for longer first
		}
		// 3. Method match (routes with method matches first)
		let method1 = a.method.is_some();
		let method2 = b.method.is_some();
		if method1 != method2 {
			return Ordering::reverse(method1.cmp(&method2));
		}
		// 4. Number of header matches (more headers first)
		let header_count1 = a.headers.len();
		let header_count2 = b.headers.len();
		if header_count1 != header_count2 {
			return Ordering::reverse(header_count1.cmp(&header_count2));
		}
		// 5. Number of query matches (more query params first)
		let query_count1 = a.query.len();
		let query_count2 = b.query.len();
		if query_count1 != query_count2 {
			return Ordering::reverse(query_count1.cmp(&query_count2));
		}
		// Finally, by order in the route list. This is the tie-breaker
		a_key.cmp(b_key)
	}

	pub fn contains(&self, key: &RouteKey) -> bool {
		self.all.contains_key(key)
	}

	pub fn remove(&mut self, key: &RouteKey) {
		let Some(old_route) = self.all.remove(key) else {
			return;
		};

		for hostname_match in Self::hostname_matchers(&old_route) {
			let entry = self
				.inner
				.entry(hostname_match)
				.and_modify(|v| v.retain(|r| &r.key != key));
			match entry {
				hashbrown::hash_map::Entry::Occupied(v) => {
					if v.get().is_empty() {
						v.remove();
					}
				},
				hashbrown::hash_map::Entry::Vacant(_) => {},
			}
		}
	}

	fn hostname_matchers(r: &Route) -> Vec<HostnameMatch> {
		if r.hostnames.is_empty() {
			vec![HostnameMatch::None]
		} else {
			r.hostnames
				.iter()
				.map(|h| HostnameMatch::from(h.clone()))
				.collect()
		}
	}

	pub fn is_empty(&self) -> bool {
		self.inner.is_empty()
	}

	pub fn iter(&self) -> impl Iterator<Item = &Arc<Route>> {
		self.all.values()
	}
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(
	feature = "schema",
	schemars(with = "std::collections::HashMap<RouteKey, TCPRoute>")
)]
pub struct TCPRouteSet {
	// Hostname -> []routes, sorted so that route matching can do a linear traversal
	inner: hashbrown::HashMap<HostnameMatch, Vec<RouteKey>>,
	// All routes
	all: HashMap<RouteKey, TCPRoute>,
}

impl serde::Serialize for TCPRouteSet {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.all.serialize(serializer)
	}
}

impl TCPRouteSet {
	pub fn from_list(l: Vec<TCPRoute>) -> Self {
		let mut rs = Self::default();
		for ls in l.into_iter() {
			rs.insert(ls);
		}
		rs
	}

	pub fn get_hostname(&self, hnm: &HostnameMatchRef) -> Option<&TCPRoute> {
		self
			.inner
			.get(hnm)
			.and_then(|r| r.first())
			.and_then(|rl| self.all.get(rl))
	}

	/// All routes for a hostname, in precedence order (oldest/alphabetical key first).
	pub fn get_hostname_routes(&self, hnm: &HostnameMatchRef) -> impl Iterator<Item = &TCPRoute> {
		self
			.inner
			.get(hnm)
			.into_iter()
			.flatten()
			.filter_map(|rl| self.all.get(rl))
	}

	pub fn insert(&mut self, r: TCPRoute) {
		if self.all.contains_key(&r.key) {
			self.remove(&r.key);
		}
		// Insert the route into all HashMap first so it's available during binary search
		self.all.insert(r.key.clone(), r.clone());

		for hostname_match in Self::hostname_matchers(&r) {
			let v = self.inner.entry(hostname_match).or_default();
			let to_insert = v.binary_search_by(|existing| existing.cmp(&r.key));
			let insert_idx = to_insert.unwrap_or_else(|pos| pos);
			v.insert(insert_idx, r.key.clone());
		}
	}

	pub fn contains(&self, key: &RouteKey) -> bool {
		self.all.contains_key(key)
	}

	pub fn remove(&mut self, key: &RouteKey) {
		let Some(old_route) = self.all.remove(key) else {
			return;
		};

		for hostname_match in Self::hostname_matchers(&old_route) {
			let entry = self
				.inner
				.entry(hostname_match)
				.and_modify(|v| v.retain(|r| r != key));
			match entry {
				hashbrown::hash_map::Entry::Occupied(v) => {
					if v.get().is_empty() {
						v.remove();
					}
				},
				hashbrown::hash_map::Entry::Vacant(_) => {},
			}
		}
	}

	fn hostname_matchers(r: &TCPRoute) -> Vec<HostnameMatch> {
		if r.hostnames.is_empty() {
			vec![HostnameMatch::None]
		} else {
			r.hostnames
				.iter()
				.map(|h| HostnameMatch::from(h.clone()))
				.collect()
		}
	}

	pub fn is_empty(&self) -> bool {
		self.inner.is_empty()
	}
}

// Helper functions for RouteMatch comparison
fn get_path_rank(path: &PathMatch) -> i32 {
	match path {
		// Best match: exact
		PathMatch::Exact(_) => 3,
		// Prefix/Regex -- we will defer to the length
		PathMatch::PathPrefix(_) => 2,
		PathMatch::Regex(_) => 2,
		PathMatch::Invalid => 0,
	}
}

fn get_path_length(path: &PathMatch) -> usize {
	match path {
		PathMatch::Exact(s) => s.len(),
		PathMatch::PathPrefix(s) => s.len(),
		PathMatch::Regex(r) => r.as_str().len(),
		PathMatch::Invalid => 0,
	}
}
