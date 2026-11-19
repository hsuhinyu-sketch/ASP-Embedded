# 工具、模型与 Agent 协作 PoC

<!-- doc-role: reference -->

本场景复用[RAG→LLM 配置与客户端](rag-llm-poc.md)，在同一 `aiSystems` 安全域内组合已有 MCP 和 A2A 能力。使用已有 HTTP API，由业务客户端按顺序传递数据，不增加中央调度器或新的聚合协议。

1. 入库并检索知识，获取通过 ContextGuard 的 chunks 与 `x-aisp-context-id`。
2. 携带相同可信 JWT、Context ID 初始化 MCP Session，通过 `tools/list` 发现允许的 Tool，再调用 `tools/call` 处理证据。
3. 携带相同 Context ID 调用模型；模型输出交给 A2A `message/send`。
4. 使用 A2A 返回的 Task ID 读取 Task，取得授权可见的 Artifact。A2A `contextId` 和 RAG 的 `x-aisp-context-id` 各有用途，不混用。

安全配置需显式允许对应 Tool、Agent 和精确出口。`crossComponent.destinations` 的分级限制同时约束 Model/Tool/Agent；MCP 配置需 `mcpSessions`，A2A 配置需 `a2aObjects` 和严格 JWT 策略。业务测试按现有 Route Key 为 A2A 注入 JWT 策略，没有在协议 Crate 添加 Host 依赖。

可重复验证命令：

```sh
python3 tests/protocol/run_full_tcp.py --profile workflow --rounds 3 \
  --binary target/debug/ai-security-platform-full --report /tmp/poc-workflow.json
python3 tests/protocol/run_full_tcp.py --profile workflow-durable --rounds 3 \
  --binary target/debug/ai-security-platform-full --report /tmp/poc-workflow-durable.json
```

测试会生成临时身份、私有状态日志及本地上游，使用真实 Gateway Listener 完成链路。模型与 Agent 是确定性替身，验证传入内容、Task/Artifact 访问和拒绝后无上游副作用，不评价模型能力或真实外部服务质量。

Task 的既有工作流绑定同时包含预算和 Context 来源；同一用户不能用另一个新 Context 接管旧 Task。配置未启用 crossComponent 时，预算绑定保持原表示。升级前已经创建、未带 Context 绑定的 Task 在启用该约束时会安全拒绝，需要新建 Task；不自动为旧元数据补发权限。取消清理、Push 和恢复继续使用同一绑定及各自原有授权。

## 纯端侧设备助手

首条端侧业务链为：客户端通过 MCP Gateway 读取设备的系统、架构和逻辑 CPU 数，再通过 LLM Gateway 让本地模型解释。客户端固定执行一次只读工具调用，不依赖模型自动选择工具；不需要云控制面、数据库、OTLP、远程身份服务、向量库或 PII Sidecar。

准备 Python 3、系统 libcrypto 和已安装模型的本地 OpenAI-compatible 服务。Ollama 可使用 `http://127.0.0.1:11434/v1`；模型须提前准备，示例不会下载模型。按所需组件构建：

```sh
cargo build --locked --release -p ai-security-platform-app --no-default-features \
  --features gateway-llm,gateway-mcp,security-s1,security-pii,tls-aws-lc \
  --bin ai-security-platform
python3 examples/edge/local_assistant.py init --state var/edge-local \
  --model qwen3.5:0.8b --model-base-url http://127.0.0.1:11434/v1
./target/release/ai-security-platform --file var/edge-local/gateway.json --validate-only
```

`init` 只创建新目录，拒绝覆盖。默认 LLM/MCP/工具端口分别为 18080/18081/18082，可用 `--llm-port`、`--mcp-port`、`--tool-port` 设置；模型地址必须是显式端口的 literal loopback HTTP URL。私有目录包含 Ed25519 本地签发密钥、10 分钟调用 JWT、公钥内联配置、预算日志和 Required Audit。签发密钥仅供本地初始化程序使用，Gateway 仍执行已有严格 JWT 验证；`token --state var/edge-local` 可重新签发调用 JWT，程序只输出文件路径。

分别在终端启动工具服务与 Gateway，再运行客户端：

```sh
python3 examples/edge/device_tools.py --port 18082
./target/release/ai-security-platform --file var/edge-local/gateway.json
python3 examples/edge/local_assistant.py run --state var/edge-local \
  --question '这台设备使用什么操作系统和 CPU 架构？'
```

工具服务仅监听 `127.0.0.1`，固定提供无参数的 `device_info`，不接受 shell、路径或写操作。Gateway 的 LLM/MCP Listener 通过 `config.bindAddress: 127.0.0.1` 限制在回环地址；管理、指标和就绪监听关闭。模型和工具出口精确列出，基础设施依赖列表为空。Enforce、可信 Agent 绑定、工具白名单、一次性 invocation、120 秒执行预算、原生模型入口 PII 和本地 Required Audit 均启用；退出时删除 Session 并取消预算。工具失败或被拒绝时不会调用模型，失败请求不自动重试；模型输出最多 96 token，截断或空答复视为失败。

保护 Session 的 stdio/SSE 上游仍按现有契约拒绝，本场景使用已有受保护的 Streamable HTTP 路径。本批没有实现高风险工具的本地审批／Capability 服务，也未接入 RAG。预算 invocation 与高风险工具 Capability 各有用途，不混用。

自动化回归使用真实 Gateway 和上述工具，模型为确定性替身；身份、租户、重放、取消、热更新、审计失败和 PII 均需通过：

```sh
python3 tests/protocol/run_full_tcp.py --profile edge-local --rounds 3 \
  --binary target/release/ai-security-platform --report /tmp/edge-local-acceptance.json
```

该命令在只有回环接口的临时网络命名空间内运行。真实模型需在同一隔离环境中使用预置的本地权重启动，再运行上述业务客户端；需单独保留模型版本、实际结果和无外网连接证据，替身回归不代表真实模型或目标设备已验收。

## 端侧安全网关接入云端模型

两份配置都使用本地 JWT、注册 Agent、模型授权、预算、原生 PII 与 Required Audit，并以供应商的固定地址作为模型出口。

| 供应商 | 网关配置 | 上游密钥 |
| --- | --- | --- |
| PAI | [pai-cloud-endpoint.yaml](../../examples/profiles/pai-cloud-endpoint.yaml) | `API_KEY` |
| MiMo | [mimo-cloud-endpoint.yaml](../../examples/profiles/mimo-cloud-endpoint.yaml) | `MIMO_API_KEY`，通过 `api-key` 头发送原始值 |

使用上文的 `init` 创建独立状态目录，然后从生成的配置导出公开 JWKS。两个供应商各用一个私有目录。下面以 PAI 为例，切换到 MiMo 时将 `provider` 改为 `mimo`，并执行对应的初始化。上游密钥由运行环境注入。

```sh
provider=pai
export EDGE_STATE_DIR="$PWD/var/$provider-cloud"
python3 - <<'PYTHON'
import json, os
from pathlib import Path

state = Path(os.environ['EDGE_STATE_DIR'])
system = json.loads((state / 'gateway.json').read_text())['aiSystems'][0]
(state / 'jwks.json').write_text(system['llm']['policies']['jwtAuth']['jwks'])
PYTHON
./target/release/ai-security-platform --file "examples/profiles/$provider-cloud-endpoint.yaml" --validate-only
./target/release/ai-security-platform --file "examples/profiles/$provider-cloud-endpoint.yaml"
```

客户端以本地 JWT 调用 `POST /v1/executions` 创建预算，再携带 `x-aisp-execution-id` 和场景配置的模型名请求 `POST /v1/chat/completions`，结束后调用 `POST /v1/executions/cancel`。使用前可通过 `token` 子命令刷新 JWT。真实接入按 TLS／鉴权、单次有界推理、JSON／SSE 和安全拒绝的顺序验证。已有探测工具通过 `--provider`、`--phase`、`--key-file` 和 `--out` 指定单独的运行条件。用 `--help` 查看完整参数。[云端探测工具](../../tests/performance/run_cloud_probe.py)
