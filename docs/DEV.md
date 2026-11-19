# AI Security Platform 开发总纲

<!-- doc-role: developer-guide -->

本文件是项目定位、开发目标、实施规范和接口约定的统一入口。开发或接手任务时先读本文件，再按改动查专题参考、源码和测试。

## 目标与范围

项目是面向端侧的模块化 AI 安全网关。按 AI 业务场景在编译期选入协议、安全能力和必要基础设施，通过共享 Runtime Host 对模型、工具、Agent 和知识库访问实施统一的安全执行。端侧产物可对接本机服务或部署明确授权的远端服务。

- 使用 Rust Workspace、Cargo features 和静态装配。支持安全配置热更新，运行时根据 YAML 装配当前产物已编入的能力。
- 以可编译的场景组合和实际业务链验收为目标。当前阶段为本地 PoC 与业务验证，真实设备和生产部署按独立验收记录判断。
- 安全能力按场景组合并保留依赖完整性。配置声明的能力缺失时拒绝加载。ASP-Embedded 提供无 UI 的网关入口。

## 架构与扩展

| 位置 | 职责 |
| --- | --- |
| `crates/gateway/app`、`composition` | CLI、场景能力声明和启动装配 |
| `crates/gateway/runtime` | 可信入口、配置与生命周期、监听、连接和凭据、最终受控执行 |
| `crates/gateway/{llm,mcp,a2a,rag}` | 协议编解码、对象建模、请求分类、路由和协议状态 |
| `crates/gateway/{contracts,protocol-core}` | 有实际消费者的跨组件契约、共享值和生命周期类型 |
| `crates/security/*` | 身份、策略与 PDP、审批与 Capability、审计、预算、撤销和数据控制 |

依赖沿 App → Runtime Host → 协议组件。协议组件的跨层依赖限于共享契约和所需安全类型。受保护的外部操作经 Host 装配的接口执行，例如 MCP Sampling 通过模型执行契约调用模型。安全扩展优先复用现有身份、授权和审计类型。由现有调用者和实际业务约束决定是否需要新增接口。[架构实施细节](architecture/README.md)

### 场景装配

| 业务 | 组件 | 专项约束 |
| --- | --- | --- |
| 推理、对话和模型路由 | LLM | 模型授权、目标出口、预算与内容控制 |
| 工具或设备操作 | MCP，可加 LLM | 会话、Task 与工具权限，高风险工具审批和一次性 Capability |
| Agent 协作 | A2A，可加 MCP、LLM 或 RAG | Agent 委托、Task 与 Artifact 归属和访问控制 |
| 知识检索与问答 | RAG，可加 LLM 或 MCP | 租户与文档 ACL、ContextGuard、Context 绑定和跨组件出口 |

发布场景 profile 将名称映射到 Cargo features。Cargo 构建 profile 决定编译优化和调试信息。运行时 `--file` 读取 `aiSystems[]`、监听、上游和安全策略。SQLite、PII 和模型路由按实际需要选入产物。启动前用相同产物运行 `--validate-only`。[场景配置与启动](README.md#安全网关场景-profile) · [发布组合](release/README.md)

## 安全与接口规范

### 受控执行

1. 有界解析请求并取得可信身份。主体、租户、Agent 与委托来自验证过的凭据或可信宿主。会话、对象和 Context 按主体、签发者、配置代际及所属资源绑定。
2. 将请求归一化为既有动作与资源，应用继承策略和专项控制。Enforce 使用默认拒绝、Deny Override 和适用的 Fail-Closed 策略。高风险调用通过审批后，使用绑定最终目标、参数和有效期的一次性 Capability。
3. 在真实发送前检查最终目标、正文分级和出口许可，完成预算准入与所要求的持久审计确认。目标、参数或配置变更，以及重试和跨协议子操作，都须经过对应的最终检查。
4. 持续检查长连接、流和异步对象的生命周期。取消、撤销、凭据过期或配置失效时，依合同停止后续发送或披露。失败响应保留协议语义，详细拒绝原因由受控审计或服务端记录承载。

安全模式默认为 `Audit`。需要强制控制的场景须明确配置 `security.mode: enforce`、可信认证和专项策略。Required Audit 按配置等待持久化确认，普通访问日志单独配置。Context 约束持有者、文档和配置状态，任意请求正文仍需按实际出口规则判断。[完整执行契约](protocol/execution-contract.md)

### 外部接口

| 面向 | 接口约定 |
| --- | --- |
| LLM | 通过模型监听调用相应模型接口。OpenAI 兼容示例用 `POST /v1/chat/completions`，模型名受路由和授权约束。 |
| MCP | 使用场景声明的 MCP 监听与传输。工具调用走 `tools/call`，受保护会话、异步 Task、反向交互和 Sampling 按启用配置及握手能力提供。 |
| A2A | 使用场景声明的 A2A 监听访问 Agent。Task 和 Artifact 访问须检查被验证的归属和权限，外部下载须检查真实目标。 |
| RAG | 入库用 `POST /v1/rag/documents`，检索用 `POST /v1/rag/query`。启用对应能力后可管理文档生命周期，并使用 `POST /v1/rag/contexts/revoke` 撤销 Context。 |

跨组件链路在配置要求时传递 `x-aisp-context-id`，并使用与原 Context 绑定的可信身份。API 保持现有请求形状、状态码、JSON-RPC 错误和流终止语义。配置字段以 Rust 序列化声明和生成的 Schema 为准。发生兼容性变化时，把迁移说明、受影响的场景模板和接口回归随实现一起更新。[配置 Schema](../schema/config.json) · [配置与能力参考](reference/configuration-guide.md) · [协议细节与回归入口](protocol/README.md)

## 实施与验收

1. 修改前查看 `git status --short`，核对实际调用链、Cargo feature 和现有验证记录。按当前授权分小批实现，保留已有工作区改动。提交、推送、PR 和发布由用户明确授权。
2. 在能力所属组件实现协议规则，在共享安全入口保持统一执行。改动覆盖历史配置、失败或中断恢复和并发语义。测试夹具放在测试目录或 `cfg(test)` 中。
3. 按变更选择验证。Rust 改动跑格式、相关单测和受影响的 feature 组合。涉及跨组件或安全执行时，跑实际产物的协议回归，并检查权限拒绝、跨租户、配置失效、撤销、重试或持久化失败对应的真实上游调用与副作用。
4. 配置或 Admin Schema 变更后运行 `cargo xtask schema` 和 `cargo xtask schema --check`，按受影响的消费方验证 Schema 与配置样例。仅修改文档时运行 `python3 tests/docs/check_docs.py`。面向公开源码的文档再跑 `python3 tests/docs/check_docs.py --public`。[Schema 与验证细节](architecture/README.md#schema-维护)
5. 汇报本轮产物、命令、实测结果和验证边界。记录首次失败的原因，区分产品、夹具和环境问题。性能变更使用同条件前后对照，记录成功率、延迟、CPU、内存以及安全控制的验收结果。

## 文档入口

- 开发目标、架构职责、实施流程及通用接口约定在本页维护。使用者从项目入口查看运行方式与场景配置。[项目入口](README.md)
- 专题文档承载参数、协议细节、可复跑示例和发布步骤。[配置参考](reference/configuration-guide.md) · [发布指南](release/README.md)
- 本地开发任务、交接状态、测量和审计证据保留在本地文档与验证目录。公开文档链接到可随源码分发的文件。
