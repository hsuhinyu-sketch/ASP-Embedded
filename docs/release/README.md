# 候选版本构建与发布准备

<!-- doc-role: reference -->

当前交付定位为 PoC 候选版本，版本号由维护者确定，建议使用 `vX.Y.Z-rc.N`。本目录不声明任何版本已经发布。生产 Linux 和设备认证尚未验收，本机性能数据不能外推到目标设备。

## 构建和核验

使用项目锁定的 Rust 1.96 工具链和 Cargo.lock，在已提交的干净工作区执行。以下命令构建原生 Linux GNU 候选。

```sh
python3 scripts/prepare_release.py --version vX.Y.Z-rc.N --profile llm --check
python3 scripts/prepare_release.py --version vX.Y.Z-rc.N --profile llm
```

示例版本需替换为维护者选择的数字版本；依赖已缓存时可增加 `--offline`。工具执行 `cargo build --locked --release --no-default-features`，显式指定本机 target 和场景 features，并用 VERSION/GIT_REVISION 固定二进制标识。打包前检查实际 `--version` JSON 的版本、提交、release profile 与 target，再次确认工作区未发生变化。

| profile | 显式编译能力 |
| --- | --- |
| llm | gateway-llm、security-s1、tls-aws-lc |
| mcp | gateway-mcp、security-s1、tls-aws-lc |
| a2a | gateway-a2a、security-s1、security-a2a-sqlite、tls-aws-lc |
| rag | gateway-rag、security-s1、tls-aws-lc |
| full | gateway-full、security-a2a-sqlite、tls-aws-lc |

五种产物均使用 `ai-security-platform` 入口，场景名体现在压缩包和 manifest 中。Full 含 LLM/MCP/A2A/RAG 与模型路由；上述组合不启用普通请求日志数据库、OTLP 或云身份 SDK。需要这些集成时另选已有 features 并重新验证，不能把不同组合的结果混用。`security-s1` 提供统一执行底座；安全配置仍须明确 Enforce、可信身份及场景所需控制，默认 Audit 行为没有改变。

输出为按场景、版本和 target 命名的 tar.gz 及 SHA-256 文件，默认位于 `target/release-dist/`。原生候选包包含可执行文件、manifest、Cargo.lock、许可（含 `LICENSE-regex-cache`）和本说明。manifest 记录 features、构建命令、源码提交、二进制构建标识及各载荷文件摘要。同名产物拒绝覆盖。

```sh
cd target/release-dist
sha256sum -c ai-security-platform-*.sha256
```

运行时所需配置和凭据由业务方提供。配置参考和第三方来源说明见源码仓库的 `docs/reference/configuration-guide.md`、`docs/third-party/README.md`。许可证条款以对应来源为准，Cargo.lock 保留依赖版本和来源；此候选产物不是独立依赖许可审计证明。

## Android ARM64 LLM 候选

首个 Android 候选为 `aarch64-linux-android` 的 `llm` CLI，链接基线 API 29。使用 x86-64 Linux GNU、仓库指定的 Rust 及 Android 目标标准库、含 API 29 链接器的 Android NDK。参考工具链为 Rust 1.96.1 和 NDK r30。构建先写入版本、源码提交、NDK 版本、API 与二进制摘要，供真机验收和最终打包共同核对。

```sh
rc_version=v0.1.0-rc.1
android_target=aarch64-linux-android
binary="${CARGO_TARGET_DIR:-target}/$android_target/release/ai-security-platform"
evidence="target/release-evidence/$android_target/$rc_version"

python3 scripts/prepare_release.py --version "$rc_version" --profile llm \
  --target "$android_target" --android-ndk "$ANDROID_NDK_HOME" --build-only

python3 tests/protocol/run_android_audit.py --binary "$binary" --worker-threads 2 \
  --report "$evidence/security.json"
python3 tests/performance/run_android_baseline.py --binary "$binary" \
  --acceptance "$evidence/security.json" --out "$evidence/performance" \
  --worker-threads 2 --concurrency 8 --rounds 1 --seconds 5 \
  --soak 600 --soak-protocols http sse --collect-stages

python3 scripts/prepare_release.py --version "$rc_version" --profile llm \
  --target "$android_target" --android-acceptance "$evidence/security.json" \
  --android-performance "$evidence/performance/report.json"
```

将 `rc_version` 换为维护者选定的版本。构建前可用 `--check` 核对输入，将它与构建命令的 `--build-only` 互换。真机阶段需要已授权的 Android 10 ARM64 设备和 ADB，可向两个验收脚本传入 `--serial` 或 `--adb`。最终打包读取先前构建的二进制，核对两个报告的构建标识、SHA-256、设备范围、有效 worker 数和持续负载结果。manifest 保留报告摘要、设备和工具链信息，原始验收数据保存在本地证据目录。[真机验收方法](../protocol/README.md#android-arm64-llm-安全验收)

Android 包附带候选配置，使用回环监听、2 个 worker、512 MiB 审计段容量和 7 天保留，要求 Enforce、可信 JWT 与持久审计。并发 8 是本次候选的验收档位。部署时将 `AISP_EXAMPLE_ISSUER`、`AISP_EXAMPLE_JWKS_FILE` 和 `AISP_EXAMPLE_STATE_DIR` 分别设为 JWT 签发者、JWKS 文件和绝对状态目录，按实际审计写入速率评估存储容量。[Android 候选配置](../../examples/profiles/android-model-gateway.yaml) · [场景配置说明](../README.md#安全网关场景-profile)

## GitHub 候选产物

新增 `Release candidate` 工作流仅由维护者手动触发，在所选提交上构建上述五种组合，对各组合的实际 release 二进制运行已有协议/安全 TCP 回归，成功后上传候选压缩包和校验和；失败证据单独保留。工作流只有 `contents: read` 权限，不创建 Release，不推送、不创建标签。尚未在远程运行的工作流不能视为已通过。

上传仓库前核对 `git status --short` 和提交范围，确保代码、测试、脚本及公开使用文档完整纳入，不要只提交 tracked 文件。阶段计划、交接说明、审查与性能报告及验证数据仅本地保留并由 Git 忽略；Python 缓存、target、环境变量文件不属于源码交付。发布时以相同提交上的 Rust CI 与候选产物回归结果为依据，最终选择版本和发布操作另行进行。

Runtime 仅记录实际运行产生的安全事件。注册到现有 IdP 客户端的 MCP 元数据应答、诊断接口及配置兼容路径保留。

发布说明应包含：组件化场景及功能、严格安全配置与内容 guard 等兼容性变化、实际验证范围、已知限制。兼容性变化和职责边界见源码仓库 `docs/CHANGELOG.md`、`docs/architecture/README.md`。候选提交必须运行对应验证，不能沿用历史测试结果。
