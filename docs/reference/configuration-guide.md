# 配置与已有能力参考

<!-- doc-role: reference -->

本文件维护配置字段、运行约束与接口行为。项目级约定、场景构建和发布步骤分别见[开发总纲](../DEV.md)、[场景配置](../README.md#安全网关场景-profile)和[发布指南](../release/README.md)。

| 查找内容 | 入口 |
| --- | --- |
| 启动与运行运维 | [热更新](#startup-configuration-and-hot-updates)、[持久审计](#managed-security-audit-operations)、[监听与就绪](#listener-lifecycle-and-readiness) |
| AI 系统配置 | [RAG](#rag-retrieval-security)、[MCP 路由](#mcp-route-configuration)、[场景装配](#ai-system-gateway-composition)、[严格出口与联合存储](#restrict-untrusted-model-payloads) |
| 身份与执行控制 | [安全管线](#composable-security-pipeline)、[通用控制](#s0s1-common-security-controls)、[高风险工具](#s3-a-high-risk-tool-gate)、[远程 PDP 与撤销](#s4-b-remote-pdp-and-delegation-revocation) |
| 请求内容 | [PII 配置与适用范围](#pii-security-component-v01) |

## Startup configuration and hot updates

The top-level `config:` section configures the Runtime Host at startup. Changing, adding,
or removing a nonempty section requires a restart. File reloads reject the
entire candidate with `config: is startup-only; restart required` before preparing protocol
resources or publishing stores. A rejected candidate keeps the current policies, listeners,
and configuration generation; an existing session is not revoked by that rejection.

Protocol configuration and security declarations under `aiSystems`, routes and backends retain
their supported hot-update behavior. A successful update still revokes the affected generation;
RAG listener topology changes still require a restart. Publication across stores is not a global
transaction.

Startup and reload use the same environment expansion and YAML/JSON parsing. Comments, key order
and formatting do not affect the comparison. An absent section, `config: null` and `config: {}`
are equivalent. Other changes to parsed startup fields, including adding explicit defaults,
require a restart. Restore the original startup section to apply a corrected dynamic update.
Rust embedders should construct `Config` through `config::parse_config`; the private startup
snapshot is skipped from configuration dumps and redacted in Debug.

`config.bindAddress` optionally selects a literal IP address for local-config protocol listeners
(`binds`, LLM, MCP and A2A), for example `127.0.0.1` for a local-only process. The default retains
the existing wildcard behavior. IPv6 addresses require IPv6 to be enabled. It is a startup-only
setting; management, stats, readiness and the separately mounted RAG listener retain their own
address settings. The [local device assistant](../examples/tool-agent-poc.md#纯端侧设备助手)
uses this with existing component features and offline identity/policy/audit configuration.


## Managed security audit operations

`config.securityAudit` configures the existing single-writer journal. Required Audit acknowledges
an operation only after its record is persisted; capacity pressure never disables this requirement.
The source directory must already exist with private permissions. Defaults remain 16 MiB per
segment, eight segments and seven days of retention; the segment capacity excludes the small
control journal. Retention deletes only expired **closed prefixes**, never unexpired evidence or
the current open segment.

```yaml
config:
  management:
    mode: diagnostic
  securityAudit:
    directory: /var/lib/ai-security-platform/audit
    maxSegmentBytes: 16777216
    maxSegments: 8
    retentionSeconds: 604800
```

These are startup settings. Each journal also persists its configuration: reopening an existing
directory requires the same canonical directory and limits. Editing the YAML and restarting does
not resize or migrate existing evidence. Directory/configuration migration and export are separate
operations; this release does not automatically rotate to a new audit authority or release evidence
on an export acknowledgement.

### Capacity status and warning

`GET /api/security/audit` is available on the existing local management listener. Diagnostic and demo modes permit the read; edge mode continues to deny it. The listener
remains restricted to loopback or Unix sockets and preserves the local Host check. This is a local
exposure policy, not remote administrator authentication. The response contains operational counters
and capacity metadata, not event records, identities, prompts, credentials or filesystem paths.

```sh
curl --fail http://127.0.0.1:15000/api/security/audit
```

Use the configured `adminAddr` port. Fields include `persistenceEnabled`, `persistenceHealthy`,
`persistenceFailures` and an optional `capacity` object. Its `state` is `ready`, `high`, `exhausted`
or `failed`; `usedBytes`, `maximumBytes`, `writableBytes`, segment counts, `controlBytes`,
`retentionSeconds`, `nextSequence`, `lastCommitMillis` and `nextReclaimAtMillis` describe the writer.
`writableBytes` includes the current segment and unused slots, not slack in closed segments.
`nextReclaimAtMillis` is the earliest closed-prefix retention deadline, not an admission promise.
Legacy or in-memory sinks have no managed capacity object.

The Host logs a warning when writable capacity reaches 20% or less, and logs exhaustion, recovery
and permanent failure on state changes. Polling does not scan files, prune evidence, reserve space
or grant authorization: status reflects the most recent writer/recovery validation. Capacity pressure
may still permit a smaller record; it remains reported until reclamation. Actual admissions always
perform their own persistence checks. Commit failure counters are cumulative and do not reset after
capacity recovery.

A capacity rejection occurs before writing that record and does not consume its durable sequence.
Later requests may reclaim eligible expired closed segments and resume with continuous committed
IDs. A true I/O error, replacement, truncation, permission violation or invalid journal remains
quarantined; repairing the filesystem requires a restart and full validation. A fitting ordinary
denial record may still be appended during pressure; it does not allow the failed operation to run.
Failed commits do not create gaps in the durable sequence.

### Offline export

Stop the Gateway and run the same binary against its YAML/JSON configuration:

```sh
ai-security-platform export-audit --file /path/to/gateway.yaml \
  --output /path/to/new-audit-archive
```

The command uses the Gateway's normal YAML/JSON parser and environment-variable expansion,
reads `config.securityAudit`, and uses the normal exclusive source writer locks and journal
validation. It does not start listeners or initialize other protocol/security state. A live
writer, missing/corrupt source, existing destination or destination inside the source directory is
rejected. The absolute output path needs an existing parent; the archive is created privately
(directory 0700 and files 0600 on Unix).

Export copies `writer.jsonl` and all retained segments byte for byte, including expired evidence
that still exists. It does not prune or modify the source. `manifest.json` records the format version,
original source path, last sequence and copied filenames/lengths; it is written after the copies,
and completion is reported only after syncing the archive. A failed export can leave an incomplete
directory: keep it for diagnosis or remove it explicitly before choosing a fresh destination. Do not
accept a nonzero command exit as a completed archive.

The archive is for evidence inspection/ingestion, not a signed bundle or an automatically portable
Gateway recovery directory. Source path/configuration binding remains in the original bytes.
Export **does not free local capacity or shorten retention**. Size the local budget for the agreed
retention window and observed audit rate, including rotation slack. If the required volume exceeds
the supported local limit, choose an explicit durable audit backend/retention/export design; neither
a larger queue nor early deletion provides the required persistence contract.

## Configuration file watch recovery

The Host registers its main configuration file watch before loading the initial configuration.
When file removal/replacement invalidates the watch or its event channel closes, the Host retries
registration at a one-second interval instead of stopping. It registers the new watch before
reading the current file, so a candidate written during the gap is also checked. A missing or
invalid candidate keeps the previous configuration and security generation. A valid candidate
retains the existing publication and revocation behavior; publication across stores is not a global transaction.

Initial watch setup failure still fails startup. The Host owns the reload task and stops it before
draining listeners, or when the Host is dropped. This recovery applies to the main configuration
file. Resource dependency watches are managed separately by ResourceManager, as described below.

The existing metrics endpoint exposes these bounded metrics, subject to `metrics.excludedMetrics`:

| Metric | Meaning |
| --- | --- |
| `agentgateway_config_reloads_total{result="success"\|"failure"}` | Completed local configuration loads, including startup. Sum the results for completed attempts. |
| `agentgateway_config_reload_last_successful` | 1 if the last completed load succeeded, otherwise 0; initially 0. |
| `agentgateway_config_watch_active` | 1 while the main configuration file watch is registered; 0 during retry, after task stop or for a static source. |
| `agentgateway_config_watch_failures_total` | Registration failures and unexpected event-channel closures. Ordinary file replacements do not increment it. |

The registration gauge is independent of the last candidate's validity and listener readiness.
Errors retain server-side detail and use stable log codes: `CONFIG_RELOAD_FAILED`,
`CONFIG_WATCH_START_FAILED`, `CONFIG_WATCH_LOST`, `CONFIG_WATCH_RETRY_FAILED` and
`CONFIG_WATCH_RESTORED`. Unexpected task failure during shutdown uses `CONFIG_WATCH_TASK_FAILED`.
Resource notification channel closure uses `CONFIG_RESOURCE_WATCH_CLOSED`;
it does not stop an otherwise active main file watch. No configuration contents or error strings
are used as metric labels.

Rust embedders pass the existing `Arc<Metrics>` to `StateManager::new(config, client, metrics)`
and retain the StateManager for the Host lifetime. Dropping it aborts the reload task.
`LocalClient::run` now returns a `JoinHandle<()>`; direct callers must own and stop that task.
Configuration reload futures are boxed at task boundaries to keep the watcher stack small.

## Dependency file watch recovery

ResourceManager retains one watch task for each referenced local dependency, including file-based
JWKS. File removal/replacement or an event-channel closure invalidates its OS watch. The same task
retries registration once per second, registers first and then reads the current file, capturing
changes made while no watch was active. The main configuration file does not need another edit
to trigger this recovery. Initial registration failure still returns an error to configuration preparation.

Missing files evict their cached bytes and notify the existing configuration reload path. Invalid
candidates keep the current accepted configuration; valid key or policy changes retain normal
validation, publication and generation revocation. Unchanged bytes do not trigger another publication.
Recovery does not grant authorization or bypass the final security checks.

Removing a dependency from the accepted configuration cancels its watch and retries. A subsequent
write to that retired path does not restore it to the active cache. File refresh checks and cache
publication share the existing active-resource lock with pruning. Background file tasks and the HTTP
refresh scheduler hold weak manager references; releasing the last ResourceManager owner aborts
registered file tasks and closes the scheduler channel. In-flight reads or HTTP operations may finish
before their temporary manager ownership is released.

Resource diagnostics use stable server-side log codes: `RESOURCE_WATCH_LOST`,
`RESOURCE_WATCH_RETRY_FAILED`, `RESOURCE_WATCH_RESTORED` and `RESOURCE_FILE_READ_FAILED`.
The main configuration's `config_watch_active` metric describes its own file watch, not every dependency.
No YAML fields, dependencies or public Rust interfaces are added by dependency watch recovery.

HTTP dependency fetches have a 10-second total deadline, including response-body reading, and
only 2xx responses are accepted. Failed refreshes retain the last cached bytes and retry after
15 seconds while the dependency remains active; normal configuration validation and generation
invalidation still apply to subsequent successful changes. A previously started refresh cannot
republish a resource while it remains retired. The scheduler processes refreshes serially, so one slow fetch may
delay another for up to its deadline. Diagnostic resource names omit URL userinfo and query
parameters; `ResourceChange.resource` now contains that sanitized name rather than the full URL.

Ordinary request logs record the HTTP path without the query string. Debug/trace logging does not
dump whole upstream requests or responses, and connection-pool debug output redacts proxy tokens.
These changes do not remove credentials from requests sent to the configured upstream.

## HTTP egress refusal responses

A data-egress refusal uses the existing authorization error: HTTP 403 with the default
`text/plain` body `authorization failed`, and request telemetry reason `Authorization`.
The same mapping applies when declared security controls prohibit request mirroring or raw
CONNECT, or when a data-egress declaration has no adapter for the outbound protocol.
Allowlist checks, exact-target validation and audit calls remain on their existing execution paths;
this change does not permit any previously blocked operation.

Detailed refusal reasons remain in server-side diagnostics. Stable log codes are
`DATA_EGRESS_DENIED`, `DATA_EGRESS_UNSUPPORTED_PROTOCOL`, `SECURITY_MIRROR_DENIED`
and `SECURITY_CONNECT_DENIED`. Internal decisions, policy identifiers and guard implementation
details are not included in the default client error body.

Authorization errors retain their existing non-retryable classification. An actual upstream HTTP
503 is still an upstream response and follows the configured retry policy. The mapping is applied
to these refusal sites only; other processing errors retain their existing conversion.
Clients that previously treated these refusals as transient HTTP 503 responses should now handle
HTTP 403. YAML, route/backend keys and public Rust interfaces do not change.

## Listener lifecycle and readiness

The Host tracks each configured socket listener, including every per-core listener.
`/healthz/ready` stays unready until initial listeners have entered their accept loops.
Socket creation, CPU affinity, runtime startup and permanent accept failures block readiness;
other listeners can continue serving through their existing security controls. Readiness failures
use the existing HTTP 500 response and identify the affected bind without returning internal errors.

Removing a bind cancels its accept loop and waits for its socket and any per-core runtime thread
to close. A later update can add the same port again. Host shutdown retains the configured graceful
drain deadlines. Explicit bind removal retains the existing cancellation behavior; it does not
promise to finish active requests on a removed bind or undo upstream side effects.

Listener failures do not trigger automatic restart or roll back an already published configuration.
Remove the failed bind, correct the cause, then add it again, or restart the Host. `--validate-only`
does not guarantee that a port will be available at runtime. Per-core mode remains experimental.
Rust consumers matching `store::BindEvent` must also handle the new `Failed(BindKey, String)` variant.

## Remote security Provider preflight

Configured `remotePdp`, `approval`, `capabilityBroker`, `delegationRevocation` and
`remoteAgentIdentity` transports are checked before startup, `--validate-only`, and supported
configuration publication. Preflight reuses the real transport constructors without sending
requests. Endpoints must be absolute HTTPS URLs without user information or fragments;
`timeoutMillis` must be positive. CA files must contain at least one parseable certificate; CA bundles
and combined client-certificate/private-key identity PEMs are supported. Broker `ttlSeconds` must
be positive and representable as a duration and expiry time.

Invalid configuration is rejected even in Audit or Shadow mode and without `dependencyEgress`.
Existing mode/composition restrictions still apply, including Enforce for Capability Broker.
A rejected hot-update candidate keeps the previous policy and generation. Restore or correct the
provider fields to publish a new candidate. A passing preflight does not verify remote availability,
trustworthiness of a response, approval, revocation status or a policy decision; those checks remain
on the actual execution path. Dependency allowlists and required audit still apply there.

Rust embedders calling the synchronous `SecurityConfig::prepare_execution` from Tokio should
use a blocking thread. The Host handles this in shared configuration normalization, including RAG-only declarations,
for startup, validation and reload. Preflight
uses temporary clients; live request transports keep their existing per-configuration cache.


## RAG retrieval security

`security-rag` is a vector-database-neutral security brick. A `SecureRetriever` first normalizes
a corpus search as `KnowledgeRetrieve` and passes it through the common `SecurityPipeline`. It
then derives a trusted `RetrievalFilter` from verified User/Agent/Tenant identity for the vector
backend and independently re-checks every returned Chunk. A Chunk is rejected unless its corpus,
tenant, ACL, expiry, provenance hash, labels, requested Chunk limit, and context-token budget all
pass. This prevents an overly broad or stale vector index from becoming an authorization bypass.

The RAG audit record contains a query hash, corpus and Chunk IDs, rejection reasons, and the
security subject; it intentionally excludes the query and Chunk text. `KnowledgeIngest`,
`KnowledgeRetrieve`, and `ContextAssemble` are now first-class runtime action types, so static or
dynamic policy can protect the full knowledge path.

`SecureIngestor` protects the other end of the chain. A document is authorized as
`KnowledgeIngest`, checked against trusted source-scheme and document-size limits, assigned a
SHA-256 provenance hash, and classified with deterministic label rules. High-risk content is sent
to a separate quarantine backend rather than the vector index. `IndexedDocument::to_chunk` then
inherits its corpus, tenant, labels, and provenance hash into every `KnowledgeChunk`, while a
trusted controller supplies only the Chunk ACL and expiry.

`gateway-rag` now composes these stages as a transport-neutral `RagGatewayAdapter`. An HTTP,
MCP, or application transport authenticates a request first, then supplies `GatewayIdentity` to
the adapter; its request models deliberately contain no Tenant, ACL, or vector-filter fields. The
adapter executes asynchronous ingestion and retrieval backends, then returns only
`GuardedContext` after the separately authorized context-assembly stage. A Qdrant or pgvector
adapter therefore implements only the backend traits and cannot bypass the common security chain.

The first concrete provider is `gateway-rag::QdrantBackend`. It receives an injected HTTP client
(so deployment can require mTLS and custom CA roots), an embedding provider, and a trusted Chunk
access policy. It writes Chunk security metadata into Qdrant Payload and performs a query with
mandatory `tenantId` and `corpusId` matches plus a `min_should` ACL condition over tenant-wide,
User, or Agent access. The `SecureRetriever` still revalidates every returned point. Qdrant
collections must be provisioned ahead of time with the matching vector dimension and keyword
Payload indexes for `tenantId`, `corpusId`, `allowedUsers`, and `allowedAgents`.

Chunk keys passed to `IndexedDocument::to_chunk` are document-local. The resulting point ID is
a deterministic UUID scoped by tenant, corpus, document and chunk key, including without a
lifecycle store. This satisfies the [Qdrant point-ID contract](https://qdrant.tech/documentation/concepts/points/#point-ids)
and prevents equal document names in different namespaces from overwriting one another.
Lifecycle-managed IDs keep their existing authority/version derivation. Non-lifecycle IDs
change from the old raw-key format; previously populated custom stores that accepted those keys
need an explicit reindex/cleanup plan. The gateway does not automatically delete legacy points.

After retrieval, `ContextGuard` separately authorizes `ContextAssemble` and examines the approved
Chunk text before it reaches the LLM. Its default Enforce mode removes Chunk content that matches
configured indirect-instruction signals; Shadow mode preserves it while producing a finding for
staged rollout. Chunks with configured sensitive labels can instead retain their provenance while
their content is replaced by a redaction marker. This deterministic signal is a PoC safety net;
a classifier or DLP engine can be added behind the same context-guard boundary later.

To opt in to the contextual rules, set the following under `aiSystems[].rag`.

```yaml
contextGuard:
  mode: enforce      # use shadow to observe findings without removing these chunks
  ruleSet: contextual
```

Use `ruleSet: legacy` or omit the field to select the original built-in rules. Contextual rules
normalize case and whitespace and drop a small, fixed set of invisible formatting characters in
the matching view. The generic English role terms `system message` and `developer message` also
need an adjacent command signal to match. The remaining built-in phrases still match directly,
including when quoted. Retained chunks keep their original content, classification, and provenance.
An explicit `indirectInstructionPatterns` list replaces either built-in set with the existing
case-insensitive literal matcher. An empty list disables indirect-instruction matching.

The rules inspect individual RAG chunks. They cover a limited set of English signals and still
miss some paraphrases, translations, encoded content, and instructions split across chunks.
Tool authorization and data-egress controls apply independently of detector findings.

For example, corpus retrieval remains deny-by-default until an explicit policy permits it:

```yaml
security:
  mode: enforce
  policies:
  - id: allow-support-knowledge-ingestion
    tenantId: tenant-a
    userId: alice
    agentId: knowledge-curator
    actionType: knowledgeIngest
    actionName: ingest
    resourceId: password-guide
    resourceType: document
    effect: allow
    enabled: true
  - id: allow-support-knowledge
    tenantId: tenant-a
    userId: alice
    agentId: support-agent
    actionType: knowledgeRetrieve
    actionName: retrieve
    resourceId: support-corpus
    resourceType: knowledgeBase
    effect: allow
    enabled: true
  - id: allow-support-context-assembly
    tenantId: tenant-a
    userId: alice
    agentId: support-agent
    actionType: contextAssemble
    actionName: assemble
    resourceId: support-corpus
    resourceType: knowledgeBase
    effect: allow
    enabled: true
```

## Composable security pipeline

`security-pipeline` provides small security bricks rather than a mandatory all-in-one gateway:

```rust
let pipeline = SecurityPipeline::new(PolicyAuthorizer::new(policies), audit_sink)
    .add_identity_control(RequiredIdentity::user_agent_tenant())
    .add_action_control(RequiredToolArguments::new("db.delete", ["recordId"]))
    .add_action_control(ToolApproval::new("db.delete", approval_provider))
    .with_capability_broker();
```

Identity controls run first, authorization is mandatory, action controls run only after an
allow decision, and the capability broker is optional. Each outcome is sent to the configured
audit sink.

The unused Rust `SecurityGateway` facade has been removed. Embedded callers can replace
`SecurityGateway::new(policies, audit_sink)` with
`SecurityPipeline::new(PolicyAuthorizer::new(policies), audit_sink)`. Add
`.with_capability_broker()` when using the local `authorize_tool` /
`consume_tool_capability` pair; keep the same pipeline instance for issuance and consumption.
Call `authorize(&request, None)` for an argument-free decision, or pass `Some(&arguments)`
when controls need Tool arguments. This method returns `Result<Decision, GatewayError>`;
denials are errors and must be handled before execution. Existing identity, argument,
approval and other required controls must still be installed. Host integrations continue
to use their configured Security Core. YAML, HTTP APIs and CLI behavior are unchanged.

## MCP route configuration

Attach `securityPipeline` under a route or MCP backend `policies` block. When this block is
present, every MCP `tools/call` is normalized from the validated JWT claims and checked before
the upstream Tool is contacted. `sub`, `agentId`/`agent_id`, and `tenantId`/`tenant_id` map to
the security User, Agent, and Tenant respectively.

```yaml
binds:
- port: 3000
  listeners:
  - routes:
    - policies:
        securityPipeline:
          requiredIdentity:
            user: true
            agent: true
            tenant: true
          policies:
          - id: allow-maintenance-delete
            tenantId: tenant-a
            userId: alice
            agentId: maintenance-agent
            actionType: toolInvoke
            actionName: db.delete
            resourceId: db.delete
            resourceType: tool
            effect: allow
            enabled: true
          requiredToolArguments:
          - toolName: db.delete
            requiredFields: [recordId]
      backends:
      - mcp:
          targets: [] # configure actual MCP targets here
```

`securityPipeline` is a compatibility entry and always enforces its declaration. If it is
configured together with `aiSystems[].security` or `securityAudit`, both declarations must permit
the operation according to their own modes. Audit/Shadow on the common declaration cannot disable
the legacy constraint. The gateway prepares both through the shared security implementation;
it does not concatenate their policy lists or share approval providers between them.

When common security enables protected MCP Sessions/Tasks, the compatibility declaration must
also permit their `mcpSessionOperation`, `mcpTaskOperation`, and applicable `mcpOperation` actions.
Session admission and renewal, Task transport and interaction checks, and stream business
reauthorization enforce both declarations. A Tool-only allow rule does not grant Session access.
Protected MCP sessions use `config.mcp.sessionTtl` (default `30m`) as their idle limit.
A successfully admitted request or an authorized, correlated protocol message refreshes activity;
periodic reauthorization, rejected calls, unrelated notifications, and raw stream bytes do not.
Activity cannot extend `mcpSessions.maxSessionSeconds`, revive expired sessions, or bypass credential,
policy, or configuration-revision checks. The stream idle and maximum-duration limits still apply.
`config.mcp` is startup configuration; this change does not add hot reload for that block.

Raw `/.well-known/` forwarding is restricted to GET/HEAD discovery with no MCP-specific controls
or security declarations on either the gateway or its resolved target.

The configuration is dynamically reloaded with the existing local configuration watcher.
MCP authorization, outbound checks, and protected-stream rechecks share normalized operations;
discovery is authorized per actual upstream server. See [protocol execution constraints](../protocol/execution-contract.md).

## AI system gateway composition

`aiSystems` assembles protocol gateways for one AI system. Each enabled gateway gets a separate
listener, route, and backend namespace, so a system may expose only LLM, LLM with endpoint-picker
inference routing, LLM plus A2A, or all three LLM/A2A/MCP gateways without changing code.

```yaml
aiSystems:
- id: support-agent # `name` remains supported for compatibility
  # RAG requires enforced policy. These three rules separately authorize document writes,
  # corpus retrieval, and final context assembly for a verified tenant principal.
  security:
    mode: enforce
    policies:
    - id: support-ingest
      actionType: knowledgeIngest
      actionName: ingest
      resourceType: document
      tenantId: tenant-a
      effect: allow
    - id: support-retrieve
      actionType: knowledgeRetrieve
      actionName: retrieve
      resourceType: knowledgeBase
      tenantId: tenant-a
      effect: allow
    - id: support-context
      actionType: contextAssemble
      actionName: assemble
      resourceType: knowledgeBase
      tenantId: tenant-a
      effect: allow
  # System-wide inference controls compile into the existing LLM execution policies.
  # They are shared by every model below, while model-level settings can refine them.
  inference:
    parameters:
      defaults:
        temperature: 0.2
        max_tokens: 1024
      overrides:
        max_tokens: 512
    quota:
      requests:
        maxTokens: 120
        tokensPerFill: 120
        fillInterval: 1m
      tokens:
        maxTokens: 100000
        tokensPerFill: 100000
        fillInterval: 1m
    routing:
      endpointPicker:
        host: 127.0.0.1:9300
      destinationMode: passthrough
  llm:
    port: 4100
    models:
    - name: support-chat
      provider: openAI
  a2a:
    port: 4101
    backend:
      host: 127.0.0.1:8100 # Agent runtime
  mcp:
    port: 4102
    targets:
    - name: customer-tools
      mcp:
        host: 127.0.0.1:8200
  # The application starts this RAG listener from the validated configuration.
  # Its HTTP input deliberately has no tenantId, ACL, or vector-store filter fields.
  rag:
    port: 4103
    qdrant:
      endpoint: https://qdrant.internal.example
      collection: support-knowledge
      quarantineCollection: support-knowledge-quarantine
      defaultChunkAccess:
        allowTenantAuthenticated: true
    embedding:
      endpoint: https://embeddings.internal.example/v1/embeddings
      model: text-embedding-3-small
    chunkMaxChars: 2000
    ingestion:
      allowedSourceSchemes: [https, s3]
      maxDocumentBytes: 10485760
    retrieval:
      maxChunks: 8
      maxContextTokens: 6000
    contextGuard:
      mode: enforce
    authentication:
      mode: strict
      issuer: https://issuer.example
      audiences: [support-rag]
      jwks:
        url: https://issuer.example/.well-known/jwks.json
```

The A2A gateway automatically adds the A2A protocol adapter to its backend route. `inference`
is a configuration-compiler input: `parameters` becomes the existing per-model LLM request
policy, `quota` becomes request and token local-rate-limit policies, and `routing` is attached to
each generated model backend so an endpoint picker can select an edge or cloud destination. The
legacy `llm.policies.localRateLimit` and `llm.policies.inferenceRouting` locations remain valid;
local rate limits compose, while routing must be declared in only one location. Ports must be
unique across all listeners. `rag` is the corresponding RAG-gateway configuration boundary: it
selects Qdrant, an OpenAI-compatible embedding endpoint, chunking, ingestion controls, retrieval
budgets, and context-injection handling. RAG requires a strict JWT validator and
`security.mode: enforce`; the runtime starts its listener and derives identity only from validated
claims before mounting `gateway_rag::router`. The route contract rejects caller-supplied tenant or
ACL fields.

The mounted RAG router exposes `POST /v1/rag/documents` and `POST /v1/rag/query`. Its host must
verify authentication and insert `gateway_rag::VerifiedGatewayIdentity` into the request before
the router runs. The document endpoint accepts only `corpusId`, `documentId`, `sourceUri`, and
`content`; the query endpoint accepts only `corpusId`, `query`, and `limit`. Therefore tenant,
principal ACL, and Qdrant filtering are exclusively derived inside the trusted processing chain.

For document ingestion, `maxDocumentBytes` limits decoded UTF-8 content. Only
`POST /v1/rag/documents` receives a JSON request limit of `6 * maxDocumentBytes + 65536`
bytes, allowing worst-case JSON escaping and a bounded envelope. The decoded content budget
is still enforced before policy/backend work: exceeding it returns 400, while exceeding the
wire limit returns 413. Other RAG JSON routes retain their existing 2 MiB limit. Hot updates
replace both the content budget and the document route limit. Invalid arithmetic overflow is
rejected during configuration validation. Embedded `RagHttpService` implementations must
provide `max_document_bytes()` from the same ingestion configuration.

With document lifecycle enabled, `POST /v1/rag/documents/lifecycle` persists Deleted before
requesting physical index cleanup. A purge failure returns 502 with the existing status fields,
including `state: "deleted"`, `purged: false`, and the current `revision`. Reads remain blocked.
Retry the delete using this revision as `expectedRevision`; successful cleanup returns 200 and
`purged: true`. The gateway does not automatically retry or restore the document. Rust callers
receive `RagGatewayError::PurgeFailed(DocumentStatus)` for this partial failure. Managed audit
records the failure as `rag:document-purge-failed`; index/quarantine failures return a sanitized
502 and record a Denied ingestion stage with a fixed backend-failure reason.

### Restrict untrusted model payloads

A dedicated RAG and direct LLM gateway can set
`aiSystems[].security.crossComponent.restrictUntrustedPayloads: true`. Enable it in
the Enforce configuration in the [RAG to LLM example](../examples/rag-llm-poc.md) and
require strict JWT authentication on both listeners. Every model request uses the
`Restricted` egress level, including free text supplied with a valid public Context.
The exact outbound destination must be permitted at all three levels. Identity, Context
ownership, expiry, revocation and document-version checks still apply. A model approved
at all three levels can process ordinary questions through the same API.

The setting defaults to false. Enabling it changes the workflow configuration binding.
Clients retrieve a fresh Context after the configuration is accepted. Configure
`security.dependencyEgress` or the deployment's `config.dependencyEgress` to approve
the RAG embedding and Qdrant endpoints as handlers of Restricted data. Include trusted
import sources and any configured security dependencies in the relevant allowlists.

This setting applies to a standalone configuration with one AI system,
RAG and fixed `openAI` models with explicit `baseUrl`. Configuration validation rejects
additional routes or listeners, A2A, passthrough, virtual models, backend tunnels,
external request processing, endpoint picking and custom request telemetry. The operator
controls access to upstreams and to any separate gateway instance. This policy governs
requests dispatched by this instance.

The same AI system can also declare one stateful Streamable HTTP MCP target with a fixed
IP and port. Configure strict MCP JWT authentication and `security.mcpSessions`. Allow each
intended tool using its exact `server/tool` name in `toolDestinations` at all three levels.
Transport setup uses the existing server allowlist and tool-derived transport permission.
MCP exposes initialization, ping, tool listing and synchronous tool calls. Clients using
sessions can close them with DELETE. The gateway builds upstream HTTP transport headers and
passes the validated protocol version and gateway-issued capability headers when applicable.
Configuration validation rejects retry and rewrite policies, Task settings and reverse
interaction settings. Prompts, resources and separate event streams are refused at runtime.

The optional App/Runtime feature `security-rag-sqlite` enables joint SQLite document/Context
state for RAG, LLM, MCP and A2A paths. It is not enabled by default. Inside
`aiSystems[].security.crossComponent`, replace `storage` with an explicit declaration:

```yaml
namespace: knowledge
maxContexts: 1024
sqlite:
  path: /absolute/private-directory/rag.sqlite
  namespace: knowledge
  maxContexts: 1024
  maxDocuments: 4096
  maxDatabaseBytes: 1048576
  busyTimeoutMillis: 100
```

Keep the existing three `destinations` policies. The nested namespace and Context capacity must
match the enclosing declaration. Remove `rag.lifecycle` and retain `rag.qdrant.integrity`:
the SQLite authority supplies the document lifecycle as well as Context state. Matching listener
generations and RAG/LLM declarations share one live store; incompatible declarations on an owned
file are rejected. Existing `storage`/`rag.lifecycle` JSONL configurations retain their behavior.
Missing build support is a configuration error. MCP Session/Task/reverse interaction and A2A
stream/recovery paths await the same Context authority. Inference/service endpoint selection
reads the current classification before scanning candidates; final dispatch checks the chosen
destination again. JSONL remains available and is never converted during startup.

Rust embedders enable `security-integration-runtime/rag-sqlite` and share a
`rag_sqlite::SqliteRagStore` through `SecurityContextStore::*_async` and the
`security_rag::lifecycle::DocumentLifecycle` interface. Synchronous Context calls to this backend
fail instead of waiting for SQL or falling back. It reuses existing document transitions, ACL
and Context-binding rules: a Context check validates documents and commits the clock highwater
in one transaction. The classification returned is not an execution permit. Final dispatch,
JWT/configuration validity, audit and budget checks remain in the Host. Streaming withholds at
most one frame until its durable check succeeds, and checks validity again before release.
Idle reauthorization belongs to the raw stream; the final adapted output also validates frames.
MCP continues polling a pending read while periodic authorization waits for storage, and
withholds its completed result until authorization succeeds. Final Task/Sampling authorization
precedes the local expiry, cancellation and single-send checks.

For an explicit **offline** import, build with `security-rag-sqlite`, stop every gateway using
either source journal, and prepare a YAML or JSON declaration with these fields:

| Field | Required value |
| --- | --- |
| `sourceSecurity` | Complete previous `aiSystems[].security`, including `crossComponent.storage`. |
| `targetSecurity` | The same security declaration, replacing only `crossComponent.storage` with `crossComponent.sqlite`. |
| `documents` | Previous `rag.lifecycle` declaration, including its namespace, capacity and journal path. |

Run the existing binary's migration subcommand, then install the target gateway configuration:

```sh
ai-security-platform import-rag-state --file /absolute/private-directory/import.yaml
```

The destination database must be new; the source files must exist and be exclusively available.
The importer reuses journal replay/transition validation, holds source locks until the destination
closes, and does not append to the journals, including full journals. It imports document state
and unexpired Context records in one transaction, preserving authority, IDs, owner, issuance,
expiry, classification, revocation and pinned versions. Only the configuration fingerprint is
rebound after confirming that every security control except storage is identical. Foreign
declarations, changed policies, malformed sources and existing targets are rejected.

Keep the source files and verify the new configuration before resuming traffic. Import does not
migrate MCP sessions, workflow budgets, capabilities, A2A Task bindings or recovery cursors;
those lifecycles retain their existing configuration invalidation behavior. Obtain new sessions
and workflow lifecycles after the change. On import failure, retain both sources and inspect the
destination before retrying: a failed transaction may leave an initialized empty database, and
an interrupted COMMIT may have an unknown outcome. The importer never deletes or merges a
destination, and never treats a failed/unknown import as permission to fall back.

`SqliteRagConfig` requires an absolute path in a private directory, a namespace, document and
Context count limits, `max_database_bytes`, and a bounded busy timeout. An open store should be
shared by its embedding application; a second owner is rejected. Its private `.owner` file must
remain beside the database. Use async `close()` for orderly shutdown. WAL/FULL commits precede
successful reads; storage, clock and WAL-reclamation failures quarantine that instance.
The page budget bounds the main database, not total disk usage. A WAL larger than 1 MiB triggers
truncate checkpoint; failure blocks further use, but one transaction can exceed that threshold.
Deleted document tombstones remain counted. Expired Contexts are reclaimed on open or issuance.
Interrupted COMMIT results may be unknown. Unknown schemas/declarations and invalid recovered
metadata are rejected; existing JSONL files are never reinterpreted or overwritten.

RAG ingestion, retrieval, and context-assembly stage events now retain the request
Subject used for policy evaluation: `tenantId`, `userId`, `agentId`, and `delegationId` use the existing
managed-audit fields. Identity comes from the trusted processing chain, including on denied
and backend-failure paths; missing values remain null, and historical records are not backfilled.
Event counts and persistence format are unchanged. JWTs, query text, and document content are
not added to these events. For Rust integrations, `IngestionAuditEvent.tenant_id` is replaced by
`subject` (read `event.subject.tenant_id`), and `ContextAuditEvent` requires the original
`security_types::Subject`. `RetrievalAuditEvent` already carries this type.

### Compile-time gateway profiles

Choose the components listed in the [scene profiles](../README.md#安全网关场景-profile) and
configure the matching listeners. Startup and hot updates reject configuration that requires a
missing feature. The optional `runtime-base` bundle includes cloud SDK, database, and OTLP
features. Choose `database`, `telemetry-otlp`, or `providers-*` individually when the deployment
only needs selected integrations. Required Audit uses the security journal described above.
The Host shares LLM data types across several build combinations.

### S0/S1 common security controls

Add `security` to an AI system to normalize identity from verified JWT claims, evaluate common
security controls, and emit a structured audit decision for LLM, A2A, MCP Tool, and inference
routing actions. `audit` records decisions, `shadow` additionally logs every decision that would
be denied, and `enforce` rejects denied requests before they reach the upstream.

```yaml
aiSystems:
- name: support-agent
  security:
    mode: shadow
    requiredIdentity: { user: true, agent: true, tenant: true }
    policies: [] # Empty policies produce a fail-closed DENY; audit/shadow do not interrupt traffic.
```

Use `enforce` only with explicit least-privilege allow policies. Policy matching is scoped by
tenant, user, agent, action, and resource; a matching deny overrides an allow and no matching
allow is denied.

```yaml
aiSystems:
- name: support-agent
  security:
    mode: enforce
    requiredIdentity: { user: true, agent: true, tenant: true }
    policies:
    - id: tenant-a-support-chat
      tenantId: tenant-a
      userId: alice
      agentId: support-agent
      actionType: modelInvoke
      actionName: invoke
      resourceId: support-chat
      resourceType: model
    effect: allow
    enabled: true
```

### S1-A registered Agent identity

`agentIdentity` turns a verified JWT `agentId` claim into a registered Agent principal. It is an
identity-stage control: it runs before policy, delegation, approval, and Capability issuance. Each
Agent is bound to one tenant, one or more verified OAuth `azp`/`clientId` values, an enabled flag,
and an optional validity period. This prevents a client from gaining an Agent's privileges by only
adding a matching `agentId` claim.

```yaml
security:
  mode: enforce
  agentIdentity:
    required: true
    agents:
    - agentId: support-agent
      tenantId: tenant-a
      clientIds: [support-agent-workload]
      enabled: true
      notBefore: 2026-09-01T00:00:00Z
      expiresAt: 2027-09-01T00:00:00Z
  policies:
  - id: allow-support-agent
    tenantId: tenant-a
    agentId: support-agent
    actionType: toolInvoke
    actionName: tickets.create
    resourceId: tickets.create
    resourceType: tool
    effect: allow
    enabled: true
```

The static registry is a local configured identity source. `AgentIdentityRegistry` is itself an identity-stage
security control, so a remote Agent Directory, certificate/SPIFFE attestation provider, or lifecycle
service can replace the source without changing protocol adapters or authorization policies.

`remoteAgentIdentity` is the implemented HTTPS/mTLS directory adapter. It is mutually exclusive
with `agentIdentity` and sends the normalized, verified request context on every Agent action; it
does not cache an allow, so an Agent disablement takes effect on the next action.

```yaml
security:
  mode: enforce
  remoteAgentIdentity:
    endpoint: https://agent-directory.security.internal/v1/identities/check
    required: true
    timeoutMillis: 100
    identityPemFile: /run/secrets/gateway-agent-directory-identity.pem
    rootCaPemFile: /run/secrets/agent-directory-root-ca.pem
```

The directory response must echo the verified `agentId`, `tenantId`, and OAuth `clientId`, return
`active: true`, and, if it supplies `expiresAt`, keep that time in the future. Network, TLS,
response-binding, inactive, and expired-directory responses are denied in `enforce` mode.

### S2 protocol-level controls

S2 turns protocol operations into the same policy vocabulary. In `enforce` mode, MCP `tools/list`
is authorized as `toolList` and every returned Tool is then filtered by its `toolInvoke` policy.
MCP Tool arguments are passed to shared required-argument controls. A2A JSON-RPC methods such as
`message/send` and `tasks/cancel` are distinct `agentInvoke` actions, while model and inference
endpoint selection remain `modelInvoke` and `inferenceRoute` actions.

```yaml
security:
  mode: enforce
  policies:
  # Permit discovery on the configured MCP target named local-tools.
  - id: allow-tool-discovery
    actionType: toolList
    actionName: list
    resourceId: local-tools
    resourceType: mcpServer
    effect: allow
  # Only this tool appears in tools/list and can be invoked.
  - id: allow-create-ticket
    actionType: toolInvoke
    actionName: tickets.create
    resourceId: tickets.create
    resourceType: tool
    effect: allow
  # Permit one explicit A2A operation; tasks/cancel remains denied.
  - id: allow-send-task
    actionType: agentInvoke
    actionName: message/send
    resourceId: support-agent-backend
    resourceType: agent
    effect: allow
  # Constrain route selection to an approved inference endpoint picker.
  - id: allow-edge-routing
    actionType: inferenceRoute
    actionName: select-destination
    resourceId: edge-picker
    resourceType: inferenceEndpoint
    effect: allow
  requiredToolArguments:
  - toolName: tickets.create
    requiredFields: [customerId]
```

### S3-A high-risk Tool gate

Declare operations that must never proceed solely because a static policy matched. The approval
control is fail-closed until a trusted approval authority is configured; `shadow` records a denied
approval without interrupting traffic.

```yaml
security:
  mode: enforce
  requiredToolApprovals:
  - toolName: records.delete
```

`approval` connects high-risk Tools to a reusable HTTPS/mTLS approval authority. The gateway sends
only the normalized `ActionRequest` plus an `argumentsHash`, never raw Tool arguments or a
caller-supplied approval header. A positive response is accepted only when its `requestId` and
`argumentsHash` match and it has a future `expiresAt`.

```yaml
security:
  mode: enforce
  requiredToolApprovals:
  - toolName: records.delete
  approval:
    endpoint: https://approval.security.internal/v1/check
    timeoutMillis: 250
    identityPemFile: /run/secrets/approval-client-identity.pem
    rootCaPemFile: /run/secrets/approval-root-ca.pem
```

The approval authority response contains `approvalId`, `requestId`, `argumentsHash`, `approved`,
and, for an allow, `expiresAt`. HTTPS/mTLS configuration errors, transport failures, non-2xx
responses, mismatched bindings, and expired approvals deny the Tool call.
The receipt is retained as `authorizationContext.approval = { approvalId, expiresAt }` in the
broker request, the protected backend's capability context, and authorization audit. The broker
must cap the token's absolute `expiresAt` at the approval deadline and echo `approvalId` in its
issue response; the gateway rejects a missing/mismatched ID, a later deadline, or a response
that arrives after expiry. It does not repeat approval to issue a token or keep an approval cache.
Deploy the matching broker before this gateway change: an older broker without the receipt/echo
contract fails closed for protected calls. YAML configuration is unchanged.

Rust integrations implement `ApprovalProvider::approved` as
`Result<Option<security_types::ApprovalGrant>, ApprovalError>` (`None` means denied).
`SecurityControl::check` returns `Result<Option<ApprovalGrant>, ControlDenial>`; ordinary controls
return `Ok(None)`, while approval controls return the receipt. The pipeline retains the receipt
on `Decision`, validates it after all action controls, and bounds the decision lifetime. A PDP
response cannot supply the approval receipt on behalf of these controls.

`capabilityBroker` connects approved high-risk MCP Tool calls to a shared capability broker. After
approval and authorization succeed, the gateway requests an opaque token bound to the normalized
request and `argumentsHash`, validates the returned binding and TTL, then injects it as the
internal `x-ai-security-capability` header for the upstream Tool/API. A caller-supplied header of
the same name is stripped and cannot be used as a grant.

```yaml
security:
  capabilityBroker:
    issueEndpoint: https://capability.security.internal/v1/capabilities/issue
    timeoutMillis: 250
    ttlSeconds: 30
    identityPemFile: /run/secrets/capability-client-identity.pem
    rootCaPemFile: /run/secrets/capability-root-ca.pem
```

The broker issues `{ token, requestId, argumentsHash, expiresAt, approvalId }` for an approval-bound call. The protected Tool/API must
consume the token once through the broker using the same normalized request and argument hash;
reuse, expiry, request mismatch, and parameter mismatch are denied. This allows broker state to be
durable and shared across gateway instances without treating a client header as authority.

`security-capability-broker` implements that shared service contract. It exposes
`POST /v1/capabilities/issue` and `POST /v1/capabilities/consume`, with one atomic consume
operation. Its PoC `InMemoryCapabilityStore` is replaceable through `CapabilityStore`; a production
store must make `consume` a durable delete-and-validate transaction. The router deliberately
requires a `BrokerPrincipal` supplied by the mTLS listener or service mesh: gateway principals may
issue, protected Tool/API principals may consume, and anonymous HTTP requests are denied.

The consuming Tool/API submits the opaque token plus the normalized `ActionRequest` and the hash
it computed from the actual Tool parameters. A successful consume returns the bound request for a
final local action/resource check; any binding mismatch burns the token before it can be replayed.
The crate API and configuration schema define the wire contract and deployment boundary.

Protected Tool/API services use the optional `security-capability-broker` `client` feature. Its
`HttpCapabilityConsumer` extracts the gateway-only capability/context headers, hashes the actual
parameters, consumes through mTLS, and validates the response before the Tool performs a side
effect. The MCP gateway strips caller-provided values of both headers and replaces them only after
it receives a broker-issued capability.

### S3-C Agent delegation

`delegations` is an additional identity-stage brick for user-owned Agents. The JWT must be
validated by the existing gateway authentication path and carry `delegationId` (or
`delegation_id`), as well as the existing user, Agent, and tenant claims. A delegation only
narrows authority: the normal `policies` allow rule must still match. An unknown grant, missing
grant, expired grant, wrong tenant, or operation outside `scopes` is denied in `enforce` mode.

```yaml
security:
  mode: enforce
  policies:
  - id: alice-support-policy
    tenantId: tenant-a
    userId: alice
    agentId: support-agent
    actionType: toolInvoke
    actionName: tickets.create
    resourceId: tickets.create
    resourceType: tool
    effect: allow
    enabled: true
  delegations:
  - id: delegation-alice-support-01
    userId: alice
    agentId: support-agent
    tenantId: tenant-a
    expiresAt: 2026-12-31T23:59:59Z
    scopes:
    - actionType: toolInvoke
      actionName: tickets.create
      resourceId: tickets.create
      resourceType: tool
```

The normalized subject and audit event retain `delegationId`, so LLM, A2A, MCP, and inference
actions can be correlated to the same user-to-Agent grant. The current adapter supports one direct
user → Agent grant. Delegation-grant issuance/revocation, signed grant exchange, and Agent →
sub-Agent delegation chains remain later S3 work.

### S4-A dynamic least privilege

`dynamicAuthorization` adds a second, context-aware PDP stage after a normal static policy
allow. It can restrict a permission to a verified JWT session (`sid`, `sessionId`) or client
(`azp`, `clientId`) and a time window. It never widens a static permission: both stages must
allow. No matching dynamic policy, an expired policy, or a PDP error is denied.

```yaml
security:
  mode: enforce
  policies:
  - id: allow-alice-ticket-create
    tenantId: tenant-a
    userId: alice
    agentId: support-agent
    actionType: toolInvoke
    actionName: tickets.create
    resourceId: tickets.create
    resourceType: tool
    effect: allow
    enabled: true
  dynamicAuthorization:
    policyVersion: s4-v1
    failureMode: failClosed
    cacheTtlSeconds: 0
    policies:
    - id: allow-current-support-session
      tenantId: tenant-a
      userId: alice
      agentId: support-agent
      actionType: toolInvoke
      actionName: tickets.create
      resourceId: tickets.create
      resourceType: tool
      sessionId: session-42
      clientId: support-console
      expiresAt: 2026-12-31T23:59:59Z
      effect: allow
      enabled: true
```

`failClosed` is the default and calls the PDP on every request. `useCachedDecision` can reuse a
still-valid decision for `cacheTtlSeconds`; use it only for explicitly low-risk read operations.
Fail-closed operation never reads or writes the decision cache. An explicitly enabled cache
holds at most 4,096 decisions per shared configuration, reclaims expired entries when full,
and consults the PDP for new keys when no cache space is available. Cache misses and PDP failures
never become an implicit Allow.
The cache key includes the policy version, subject, action, resource, session, and client, so it
cannot be reused across a different security context. The current implementation provides `LocalDynamicPdp` and a
replaceable `DynamicPdp` trait. A trusted HTTPS remote PDP can now be selected through
`remotePdp` as described below.

### S4-B remote PDP and delegation revocation

The security core now defines the transport-neutral remote PDP contract. A runtime adapter must
send a versioned `RemotePdpRequest` containing only normalized identity, delegation, action,
resource, and authorization context. Its `RemotePdpResponse` is accepted only when all of the
following match:

- `requestId` is the request being authorized;
- `policyVersion` is the version expected by the gateway, when one is pinned;
- `expiresAt` is in the future.

The returned policy version and expiry are written to the structured audit event. A cached decision
is bounded by the smaller of the local TTL and PDP `expiresAt`, so a remote allow cannot survive
past its PDP validity window.

The running gateway now supplies the HTTP/mTLS transport. It accepts only absolute `https` PDP
URLs, has a required bounded `timeoutMillis` (250 ms by default), reuses one Rustls HTTP client
per loaded AI-system configuration, and maps invalid TLS/configuration, timeout, network, non-2xx,
or invalid-response failures to a deny. `identityPemFile` references one PEM containing the PDP
client certificate and private key; `rootCaPemFile` pins an additional private CA when needed.
Neither a bearer token nor raw Tool arguments are sent to the PDP.

```yaml
security:
  mode: enforce
  dynamicAuthorization:
    policyVersion: pdp-bundle-2026-09-14
    failureMode: failClosed
    cacheTtlSeconds: 0
  remotePdp:
    endpoint: https://pdp.security.internal/v1/decisions
    timeoutMillis: 250
    identityPemFile: /run/secrets/pdp-client-identity.pem
    rootCaPemFile: /run/secrets/pdp-root-ca.pem
```

The current gateway security hook is synchronous, so the current adapter uses `reqwest`'s bounded blocking
client. Moving the hook to async I/O is a runtime-performance follow-up; it does not change the
PDP contract or security semantics.

`DelegationRevocationCheck` and `DelegationRevocationProvider` provide the corresponding realtime
revocation brick. The in-process `DelegationRevocationRegistry` remains useful for tests, while
`delegationRevocation` now connects every gateway instance to a shared HTTPS/mTLS source. A
request carrying a verified `delegationId` issues an uncached `POST` on every protected action:

```json
{ "protocolVersion": "v1", "delegationId": "delegation-alice-support-01" }
```

The source must return the same `delegationId` and a Boolean `revoked` value. A mismatched ID,
timeout, TLS/network failure, non-2xx response, or malformed response is fail-closed; requests
without a delegation do not query the source. This makes a revocation visible to all configured
gateway instances on their next protected request.

```yaml
security:
  delegationRevocation:
    endpoint: https://identity.security.internal/v1/delegations/revocation
    timeoutMillis: 100
    identityPemFile: /run/secrets/revocation-client-identity.pem
    rootCaPemFile: /run/secrets/identity-root-ca.pem
```

## PII Security Component V0.1

`security-pii` 是协议无关的可选内容安全组件，集中检查经本网关受控模型入口发送的请求。可信身份/授权 → 请求默认值、转换前变更、prompt enrichment 与原请求 guard → 完整请求 PII → Provider 编码 → 原最终授权、配置失效、出口、预算和受控发送。直接模型调用、MCP Sampling 和业务组装的 RAG→LLM 使用同一检查点。RAG 本身只执行原有检索授权、Chunk ACL、ContextGuard、分类、Provenance 和预算，返回授权原文；不再额外做 PII。

### 编译与配置

仅原生检测不需要 Python 或 Sidecar：

```sh
cargo build --locked -p ai-security-platform-app --no-default-features \
  --features gateway-llm,security-s1,security-pii,tls-aws-lc \
  --bin ai-security-platform
```

需要 Analyzer 时，将 `security-pii` 替换为 `security-pii-presidio`。该 feature 保留原生检测，不自动选择外部后端，也不隐式编译 LLM/RAG 协议。现有五种候选发布 profile 默认不启用 PII；未编译相关能力或未选择 LLM 时，启用配置明确拒绝。缺省 `security.pii`、`enabled: false` 或 `mode: disabled` 不创建检测组件；旧 LLM regex guardrails 配置保持。原先未发布的 `rag.pii` 已移除，Host 会明确报错并要求迁移。

在现有 `aiSystems[].security` 内增加下列配置；该 aiSystem 必须包含 LLM。可信模型路由/后端也可使用已有 `securityAudit` 安全配置入口；继承的 PII 要求不会被子策略省略而消除。完整身份与模型配置见[RAG→LLM 示例](../examples/rag-llm-poc.md)：

```yaml
pii:
  enabled: true
  mode: enforce
  backend: native
  language: en
  timeoutMs: 1000
  maxTextBytes: 65536
  maxOutputBytes: 131072
  maxResponseBytes: 131072
  maxFindings: 256
  policy:
    entities:
      EMAIL_ADDRESS: { action: replace, value: '[EMAIL_ADDRESS]' }
      PHONE_NUMBER: { action: mask }
      IP_ADDRESS: { action: redact }
```

`mode` 为独立内容控制模式，不能代替原安全配置：PII 不授予模型调用权限，身份、ModelInvoke 授权及其他既有安全要求仍需配置。`audit`/`shadow` 产生检测/错误审计，不改写也不阻断正文；`enforce` 执行策略，检测异常拒绝模型出站，禁止静默转为未检测透传。V0.1 没有 Enforce fail-open 开关。`enabled` 在提供配置对象时默认 true，`mode` 默认 enforce，`backend` 默认 native。

动作支持 `detectOnly`、`replace`、`mask`、`redact`、`block`。Mask 替换每个敏感 Unicode 字符为 `*`，Redact 删除对应片段，Block 阻止整个模型请求出站，返回固定 403。重叠改写合并其覆盖范围，冲突采用 Redact > Mask > Replace；任何 Block 优先阻断。未命中的正文保持。配置可按不同 aiSystem/模型安全域分别选择实体及动作，不根据用户文本猜测是否允许外传。

原生后端提供 Email 格式检测、由 phonenumber 元数据校验的有限区域 Phone 检测，以及由 Rust IpAddr 校验的 IPv4/IPv6；它们是确定性信号，不是身份真实性证明。可用 `customRules: { EMPLOYEE_ID: 'EMP-[0-9]{4}' }` 配置其他规则，并在 `policy.entities` 指定相应动作。`customRules` 仅适用于 Native；Presidio 配置非空 customRules 会拒绝，额外识别器应部署到 Sidecar。未知原生实体、非法/空规则、超限参数和未知 PII 字段拒绝配置；没有可靠姓名识别器时，不声称姓名已脱敏。旧 SSN/银行卡 regex 配置没有被替换或升级为可靠校验器。

PII Core 的 Finding 使用 UTF-8 字节范围 `[start,end)`；Presidio Adapter 将 Python Unicode 字符下标转换为字节边界。重复结果规范化，无效范围/置信度/未知实体拒绝。请求投影保留消息角色和工具关联；工具参数修改后必须仍是合法 JSON。

PII 检查消息正文、系统指令、历史、工具结果与参数；工具定义/Schema、metadata、`user`、停止文本、工具名称/关联标识及未知扩展继续作为只读数据检查，需要改写时拒绝。仅排除根级类型正确的已知控制字段：`model`、`stream`、`temperature`、`top_p`，以及对应请求格式的 token 上限、Completions 的 penalty/seed 和仅含布尔 `include_usage` 的 `stream_options`；固定角色与已验证的内容 `type` 也不送入检测器。模型名仍受原路由/授权控制，不属于正文脱敏范围。未知角色、控制字段的异常类型、带扩展的 `stream_options` 不因此获得豁免；metadata/工具参数内部即使含有同名键，也继续检查。

`maxTextBytes`/`maxOutputBytes` 限制整个序列化请求，包含未送检的控制字段；`maxFindings` 同时限制单片段和完整请求，最多 128 个送检片段、16 层内容结构，`timeoutMs` 也限制一次完整检查。原生检测在候选间检查截止时间并定期让出执行权；单次同步解析不能硬抢占，完成后若已超期，Enforce 拒绝模型出站，Audit/Shadow 记录错误并保留原文。因此该参数不是严格的墙钟耗时上限。计价/分词在 PII 之后沿原机制执行，原 Context Budget 不变。

### 可选的本地 Presidio Analyzer

Adapter 使用官方 `POST /analyze`，只发送文本、语言、配置的实体列表并关闭 decision-process 返回；匿名化在 Rust 本地完成，不需要 Anonymizer 服务。接口依据见 [Presidio REST 定义](https://github.com/microsoft/presidio/blob/main/docs/api-docs/api-docs.yml)。

按照[官方启动示例](https://github.com/microsoft/presidio/blob/main/docs/getting_started/getting_started_text.md)，PoC 可使用官方容器：

```sh
docker run --rm --name aisp-presidio \
  -p 127.0.0.1:5002:3000 mcr.microsoft.com/presidio-analyzer:latest
```

这里的 latest 是官方快速开始标签，实际环境应固定经过验证的镜像摘要；本轮没有拉取镜像或模型，不能将协议替身测试描述为官方 NLP 模型验收。Sidecar 应按其版本关闭请求正文/调试日志，且不能暴露到外部网络。新增 PII 组件不记录原文、匹配片段、上游错误正文或检测响应；它不负责净化其他既有组件显式启用的请求正文日志，不能将局部 PII 保护当作全平台日志匿名化保证。

```yaml
pii:
  enabled: true
  mode: enforce
  backend: presidio
  presidioEndpoint: http://127.0.0.1:5002
  language: en
  timeoutMs: 1000
  policy:
    entities:
      EMAIL_ADDRESS: { action: replace, value: '[EMAIL_ADDRESS]' }
      PHONE_NUMBER: { action: block }
```

V0.1 仅接受 literal loopback IP（127.0.0.1/IPv6 loopback 等）和根路径或 `/analyze`，拒绝 DNS 名称、远程地址、userinfo、query、fragment 与任意检测路径；关闭重定向及环境代理。普通 HTTP 请求不能选择后端或地址。若配置 `security.dependencyEgress`，需在已有 `guardrail` 类别显式允许实际 Sidecar host:port，并保持原 Qdrant/Embedding 许可；HTTP loopback 需显式满足该策略的 TLS 规则。候选本地配置发布前会用固定非敏感文本检查 Analyzer 响应，服务不可达/响应非法时拒绝新配置，保留旧配置。

用合成文本检查 Analyzer（返回结果不包含原始匹配文本）：

```sh
curl --fail http://127.0.0.1:5002/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"Contact alice@example.com","language":"en","entities":["EMAIL_ADDRESS"],"return_decision_process":false}'
```

启动网关后，直接发送模型请求，或按 RAG→LLM 示例将授权 chunks 与用户问题、历史消息、工具结果组装为请求。Completions、Messages、Responses 的支持文本在完整组装后检查；多模态、远程 previous_response_id/conversation/prompt 等无法本地检查的内容，Enforce 明确拒绝。PII 审计使用现有安全事件持久化，事件类型 `piiInspection`，仅含实体类别/数量、模式、改写结果及固定错误，不携带正文/匹配片段。启用 ModelInvoke 的 Required Audit 时，PII 审计确认持久化后才能继续发送。该事件是内容检查结果，不是上游已执行的回执。

### 验证与边界

```sh
cargo test --locked -p security-pii --no-default-features
cargo test --locked -p security-pii -p gateway-llm --all-features
cargo test --locked -p security-integration-runtime --features pii --lib pii::tests
python3 tests/protocol/run_full_tcp.py --profile pii --rounds 3 \
  --binary target/debug/ai-security-platform --report /tmp/aisp-pii.json
```

后一个命令需使用已经编译 LLM、MCP、RAG 与 `security-pii-presidio` 的网关；驱动在隔离 loopback 验证直接模型请求、RAG→LLM、MCP Sampling 和可控 Analyzer HTTP 契约，不需要 Python NLP 包、云模型或权重。首次失败和固定轮次均保留。

V0.1 只覆盖经本网关受控模型入口的请求文本；响应/SSE 输出、HTTP headers、多模态、直接 RAG 返回、入库/Embedding 原文、MCP 工具和 A2A 对外载荷不覆盖。外部 Agent 绕过本网关调用模型也不在保护范围。`stream: true` 的完整请求仍可检查，但不表示 SSE 响应已做实体脱敏。检测按结构化片段执行，不保证识别跨字段拼接、编码或其他混淆实体。Context ID 继续是身份/策略/文档凭证，不是正文净化证明；现在 `security.pii` 参与原安全配置指纹，变更会沿原机制使相关旧 Context 和请求失效，未新增第二套撤销系统。

模型入口启用 PII Enforce 时，仅接纳上述 Completions、Messages、Responses 支持文本；Embeddings、Rerank、TokenCount、Detect、Passthrough、Realtime 等未支持路由明确拒绝。Audit/Shadow 对这些路由记录 unsupported 后保留原行为，不声称已检查其内容。RAG 内部直接调用 Embedding 服务不经过该模型入口，不会因此自动加入 PII。

后续 NER/GLiNER/ONNX 后端实现 `PiiDetector` 即可接入同一规范化、策略、匿名化和错误边界；模型实体需显式映射为部署配置的实体名，不能创建新身份/授权引擎。中文姓名质量、模型权重、跨帧缓冲与可逆密钥管理分别验证，不在 V0.1 中预建空框架。

Host 在发布配置前等待 PII readiness。Native 启用 `PHONE_NUMBER` 时，检测器通过阻塞任务准备共享电话元数据及现用地区的常见匹配路径；这会提前驻留缓存并增加首次准备时间。初始化位于单次文本检测的 `timeoutMs` 之外，检测期限与超期结果复核仍按原配置执行。仅邮箱、禁用 PII 和 Presidio 不执行此电话初始化；Presidio 保留原 Analyzer readiness 请求。数据相关的首次匹配和缓存淘汰仍可能产生同步开销，不承诺硬实时返回。

嵌入使用 `PiiEngine` 时，应先等待 `check_ready().await`，成功后再向请求暴露引擎。替代检测器可实现 `PiiDetector::prepare` 完成本地资源准备，默认无需额外准备；准备失败会使 readiness 失败，包括 Audit/Shadow 模式。Host 对同一准备状态去重，取消后不会发布半就绪引擎，可重新准备；已开始的本地阻塞初始化不能硬抢占，但不会携带业务正文或直接产生业务副作用。

### 离线数据集评测入口

Gretel 和 Nemotron-PII 的转换器会核对来源文件与标注，输出统一数据后由同一驱动评分。通过固定样本和本地模型替身验证实体检测、遮盖与拒绝路径。标注质量、电话范围和地区版本会影响指标。使用各脚本的 `--help` 查看输入和产物参数。[Gretel 转换](../../tests/performance/gretel_dataset.py) · [Nemotron 转换](../../tests/performance/nemotron_dataset.py) · [评测驱动](../../tests/performance/run_pii_dataset.py)
