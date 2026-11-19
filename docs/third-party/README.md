# Third-party source dependencies

<!-- doc-role: vendor-reference -->

> 上游/第三方依赖说明，仅适用于对应依赖；保留原文与许可语境。平台架构见源码仓库 `docs/architecture/README.md`。


The source directory [crates/third-party](../../crates/third-party) contains vendored or forked third-party libraries retained as source dependencies.
They are not AI Gateway Platform runtime modules.

| Directory | Rust packages | Purpose |
| --- | --- | --- |
| `cel-fork` | `cel`, `cel-derive` | CEL implementation required by policy and configuration processing. |
| `htpasswd-verify-fork` | `htpasswd-verify-fork` | HTTP basic-auth verification dependency. |
| `regex-cache` | `regex-cache` | Bounded regex cache used by native PII phone validation; one lookup per CachedRegex hit. |

New platform functionality belongs under `crates/gateway`, `crates/security`, or
`crates/platform`; changes here should be limited to dependency maintenance.

Vendored documentation is archived here: [htpasswd-verify](htpasswd-verify-fork/README.md),
[cel-derive](cel-fork/cel-derive/README.md), [CEL changelog](cel-fork/cel/CHANGELOG.md).

The optional PII evaluation uses the synthetic
[Gretel PII Masking English dataset](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1)
by Gretel, licensed under Apache-2.0. The evaluator pins its test split at revision
`e06eb1499ca8d54470f085021cd8e54f9efac7fd`. Downloaded data and its original README
remain local under `target/`; they are not bundled with the gateway or its releases.
PyArrow is an optional evaluation tool in a separate Python environment, not a gateway runtime dependency.

The supplemental evaluation uses [NVIDIA Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII),
by Amy Steier, Andre Manoel, Alexa Haushalter and Maarten Van Segbroeck, published by NVIDIA in 2025
under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
The test file is pinned at `b70ffaf5ff39e079776134c5bf4381f00a9fd1ed`; a public mirror is accepted
only when its bytes match the official SHA-256. Local preparation samples by locale and format,
converts character offsets to UTF-8 byte offsets, and handles numeric/case-normalized annotation text
without changing source positions. Neither the original data nor the prepared subset is bundled.

## regex-cache source and local changes

The vendored [regex-cache source](../../crates/third-party/regex-cache) is based on
`regex-cache` 0.2.1 from crates.io, upstream repository
<https://github.com/1aim/rust-regex-cache>. The original package SHA-256 is
`2f7b62d69743b8b94f353b6b7c3deb4c5582828328bcb8d5fedf214373808793`.
The [MIT license](../../crates/third-party/regex-cache/LICENSE) and source copyright
notices are retained; release archives include `LICENSE-regex-cache`.

The root Cargo patch uses this source for the transitive `phonenumber` dependency.
The existing Runtime PhoneRecognizer also uses `phonenumber`; disabling the optional
security-pii component does not remove that pre-existing dependency.
The local algorithm change is confined to `src/cache.rs`: a private generic callback
performs a CachedRegex operation after one cache lookup on a hit. Public interfaces,
source-string cache keys, builder-on-miss behavior, capacity, LRU order, locking and
panic poisoning remain unchanged. Public RegexCache.configure/compile/save retain
the upstream implementation. Shared-lock contention is still possible.

Other source differences are repository formatting, local package/readme metadata,
and `tests/cached_contract.rs`. The tests cover operation equivalence, input-backed
capture lifetimes, capacity/LRU behavior, compile failures, panic poisoning and
concurrent eviction. Run `cargo test --locked -p regex-cache` after dependency updates;
review upstream changes before replacing the patched source.
