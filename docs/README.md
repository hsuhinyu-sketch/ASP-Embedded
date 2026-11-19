# ASP-Embedded

<!-- doc-role: entrypoint -->

面向端侧部署的无 UI 模块化 AI 安全网关。按业务场景编译组合 LLM、MCP、A2A、RAG 及所需安全能力。

开发和接手任务从项目定位、实施规范及接口约定读起。[开发总纲 DEV.md](DEV.md)

## 构建与运行

使用 [rust-toolchain.toml](../rust-toolchain.toml) 指定的 Rust 工具链。示例构建不带其他协议实现的模型网关：

```sh
cargo build --locked --release -p ai-security-platform-app \
  --no-default-features --features gateway-llm,security-s1,tls-aws-lc \
  --bin ai-security-platform
./target/release/ai-security-platform --file /path/to/config.yaml --validate-only
./target/release/ai-security-platform --file /path/to/config.yaml
```

配置与凭据由业务方提供。使用 `--no-default-features` 才能排除默认组合；五种场景的候选版本打包方式见[发布指南](release/README.md)。

安全场景须显式配置 Enforce、可信认证和专项策略。[受控执行规范](DEV.md#受控执行)

可选的 `security-pii` 提供原生 PII 检测与统一模型请求出口脱敏，`security-pii-presidio` 增加本地 Presidio Analyzer Adapter。配置、模式及覆盖边界见[PII V0.1 使用说明](reference/configuration-guide.md#pii-security-component-v01)。

## 安全网关场景 profile

从 `examples/profiles/` 选择一份运行配置。每份文件的首行列出完整 Cargo features。表中列出场景专用 features，另需公共的 `security-s1` 和 `tls-aws-lc`。

| 场景 | 场景专用 features | 配置 |
| --- | --- | --- |
| 模型推理与固定出口 | `gateway-llm` | [model-gateway.yaml](../examples/profiles/model-gateway.yaml) |
| 固定工具和会话授权 | `gateway-mcp` | [tool-gateway.yaml](../examples/profiles/tool-gateway.yaml) |
| Agent 调用、Task 归属和 SQLite 恢复 | `gateway-a2a,security-a2a-sqlite` | [agent-gateway.yaml](../examples/profiles/agent-gateway.yaml) |
| 知识库写入、检索和 ContextGuard | `gateway-rag` | [knowledge-gateway.yaml](../examples/profiles/knowledge-gateway.yaml) |
| 知识问答和 Context 绑定 | `gateway-rag,gateway-llm` | [knowledge-assistant.yaml](../examples/profiles/knowledge-assistant.yaml) |
| 设备助手、工具调用和模型出口脱敏 | `gateway-llm,gateway-mcp,security-pii` | [device-assistant.yaml](../examples/profiles/device-assistant.yaml) |
| 知识、模型与固定工具的严格出口 | `gateway-rag,gateway-llm,gateway-mcp` | [strict-knowledge-tools.yaml](../examples/profiles/strict-knowledge-tools.yaml) |
| 跨 Agent 业务链和持久 Task | `gateway-rag,gateway-llm,gateway-mcp,gateway-a2a,security-a2a-sqlite` | [multi-agent-workflow.yaml](../examples/profiles/multi-agent-workflow.yaml) |

示例监听在回环地址。网关的 LLM、A2A、MCP 与 RAG 端口分别为 14100、14101、14102 和 14103，默认一次运行一个场景。模型、Agent 与工具分别指向本机 18000、18100 和 18200，RAG 使用 18001 上的 Embedding 和 6333 上的 Qdrant。按部署替换服务地址时，同时调整对应出口许可、模型名或工具名。RAG 入库授权示例要求 `tenant-a` 的 `operator-a` 负责写入，其余请求同样需要可信的用户与租户。启用跨组件 Context 后，后续模型、工具或 Agent 请求应使用同一身份并携带有效 Context。

运行前设置签发者、公开 JWKS 文件与绝对状态目录。JWT 需要有效的 `iss`、`exp`、`sub` 和 `tenant_id`，`aud` 使用场景文件名去掉 `.yaml` 后的名称。跨 Agent 示例还要求 `agent_id: workflow-agent` 与 `client_id: workflow-client`。以下展示严格出口场景的启动命令，执行前将签发者和 JWKS 路径替换为自己的值。

```sh
profile=strict-knowledge-tools
export AISP_EXAMPLE_ISSUER=https://id.example.invalid
export AISP_EXAMPLE_JWKS_FILE=/absolute/path/to/public-jwks.json
export AISP_EXAMPLE_STATE_DIR="$PWD/var/example-gateway"
install -d -m 700 "$AISP_EXAMPLE_STATE_DIR/$profile/audit"

# RAG 示例需要来自密钥存储的向量完整性密钥。
# 首次创建独立测试库可用 openssl rand -hex 32，并在后续启动时复用同一值。
export AISP_EXAMPLE_VECTOR_KEY='<64 个十六进制字符>'

cargo build --locked --release -p ai-security-platform-app --no-default-features \
  --features gateway-rag,gateway-llm,gateway-mcp,security-s1,tls-aws-lc \
  --bin ai-security-platform
./target/release/ai-security-platform --file "examples/profiles/$profile.yaml" --validate-only
./target/release/ai-security-platform --file "examples/profiles/$profile.yaml"
```

带 RAG 的示例使用专属 Qdrant 主集合和隔离集合。先按 Embedding 向量维度创建集合及租户、语料和 ACL 所需索引。配置校验通过后，再用实际对端执行端到端业务检查。[RAG 配置参考](reference/configuration-guide.md#rag-retrieval-security)

## 文档

- [架构与扩展边界](architecture/README.md)
- [配置与已有能力参考](reference/configuration-guide.md)
- [协议职责](protocol/README.md)与[统一安全执行约束](protocol/execution-contract.md)
- [RAG → LLM 示例](examples/rag-llm-poc.md)与[工具／Agent 协作示例](examples/tool-agent-poc.md)
- [纯端侧设备助手](examples/tool-agent-poc.md#纯端侧设备助手)：本地只读工具 → 本地模型，复用身份、预算、PII 与持久化审计。
- [候选版本构建与发布](release/README.md)、[变更记录](CHANGELOG.md)、[第三方来源说明](third-party/README.md)

开发交接、阶段计划、审查记录、性能原始数据和本机验证结果仅在本地保留，不属于仓库公开文档或 release 包。文档提交检查：`python3 tests/docs/check_docs.py --public`。

Apache License 2.0，见 [LICENSE](../LICENSE)。
