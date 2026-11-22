#!/usr/bin/env python3
"""Build and package a release candidate from a clean checkout; never publish."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    "llm": "gateway-llm,security-s1,tls-aws-lc",
    "mcp": "gateway-mcp,security-s1,tls-aws-lc",
    "a2a": "gateway-a2a,security-s1,security-a2a-sqlite,tls-aws-lc",
    "rag": "gateway-rag,security-s1,tls-aws-lc",
    "full": "gateway-full,security-a2a-sqlite,tls-aws-lc",
}
VERSION = re.compile(r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
ANDROID = "aarch64-linux-android"
ANDROID_API = 29
ANDROID_PROFILE = "llm"
ANDROID_CONFIG = "android-model-gateway.yaml"
ANDROID_AUDIT_BYTES = 512 * 1024 * 1024
ANDROID_RETENTION_SECONDS = 7 * 24 * 60 * 60


def output(command, **kwargs):
    return subprocess.check_output(command, cwd=ROOT, text=True, **kwargs).strip()


def validate_version(value):
    if not VERSION.fullmatch(value):
        raise ValueError("version must be a tag such as v0.1.0-rc.1")
    return value


def check_source():
    if output(["git", "status", "--porcelain", "--untracked-files=all"]):
        raise ValueError("release packaging requires a clean committed checkout")
    return output(["git", "rev-parse", "HEAD"])


def validate_build(info, version, revision, target):
    expected = {"version": version, "git_revision": revision,
                "build_profile": "release", "build_target": target}
    if any(info.get(key) != value for key, value in expected.items()):
        raise ValueError("binary build metadata does not match the release inputs")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def package(binary, destination, version, profile, revision, target, info, command, *, android=None):
    validate_build(info, version, revision, target)
    name = f"ai-security-platform-{profile}-{version}-{target}"
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / f"{name}.tar.gz"
    checksum = destination / f"{name}.sha256"
    if archive.exists() or checksum.exists():
        raise ValueError("release output already exists; use a new output directory")
    with tempfile.TemporaryDirectory(prefix=".package-", dir=destination) as temporary:
        staging = Path(temporary) / name
        staging.mkdir()
        shutil.copy2(binary, staging / "ai-security-platform")
        if android is not None:
            if digest(staging / "ai-security-platform") != android["binarySha256"]:
                raise ValueError("staged Android binary differs from the verified artifact")
            shutil.copy2(ROOT / "examples/profiles" / ANDROID_CONFIG, staging / ANDROID_CONFIG)
        for source, filename in ((ROOT / "LICENSE", "LICENSE"),
                                 (ROOT / "Cargo.lock", "Cargo.lock"),
                                 (ROOT / "docs/release/README.md", "RELEASE.md"),
                                 (ROOT / "crates/platform/pool/LICENSE", "LICENSE-platform-pool"),
                                 (ROOT / "crates/third-party/regex-cache/LICENSE", "LICENSE-regex-cache")):
            shutil.copy2(source, staging / filename)
        manifest = {"version": version, "profile": profile, "features": PROFILES[profile].split(","),
                    "gitRevision": revision, "buildInfo": info, "buildCommand": command,
                    "files": {path.name: digest(path) for path in sorted(staging.iterdir())}}
        if android is not None:
            manifest["android"] = android
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        pending = Path(temporary) / archive.name
        with tarfile.open(pending, "w:gz") as stream:
            stream.add(staging, arcname=name)
        pending_checksum = Path(temporary) / checksum.name
        pending_checksum.write_text(f"{digest(pending)}  {archive.name}\n")
        if android is not None and check_source() != revision:
            raise ValueError("checkout changed while staging the Android candidate")
        try:
            os.link(pending, archive)
        except FileExistsError as error:
            raise ValueError("release output already exists; use a new output directory") from error
        try:
            os.link(pending_checksum, checksum)
        except BaseException:
            archive.unlink()
            raise
    return archive


def build_command(profile, target, offline=False):
    command = ["cargo", "build", "--locked", "--release", "--target", target,
               "-p", "ai-security-platform-app", "--no-default-features",
               "--features", PROFILES[profile], "--bin", "ai-security-platform"]
    if offline:
        command.append("--offline")
    return command


def build_paths(target):
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target_dir.is_absolute():
        target_dir = ROOT / target_dir
    binary = target_dir / target / "release/ai-security-platform"
    return binary, binary.with_name("ai-security-platform.android-build.json")


def android_toolchain(ndk):
    ndk = ndk.resolve()
    properties = (ndk / "source.properties").read_text()
    ndk_revision = re.search(r"^Pkg\.Revision\s*=\s*(\d+\.\d+\.\d+)\s*$", properties, re.MULTILINE)
    if ndk_revision is None:
        raise ValueError("could not read the Android NDK revision")
    rust = dict(line.split(": ", 1) for line in output(["rustc", "-vV"]).splitlines() if ": " in line)
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if rust.get("host") != "x86_64-unknown-linux-gnu" or not rust.get("release", "").startswith(channel + "."):
        raise ValueError(f"use the repository Rust {channel} toolchain on an x86-64 Linux GNU host")
    rust_target = Path(output(["rustc", "--print", "target-libdir", "--target", ANDROID]))
    if not any(rust_target.glob("libstd-*.rlib")):
        raise ValueError(f"install Rust standard libraries for {ANDROID}")
    bin_dir = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    compiler = bin_dir / f"{ANDROID}{ANDROID_API}-clang"
    settings = {"CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER": str(compiler),
                "CC_aarch64_linux_android": str(compiler),
                "CXX_aarch64_linux_android": str(compiler) + "++",
                "AR_aarch64_linux_android": str(bin_dir / "llvm-ar")}
    readelf = bin_dir / "llvm-readelf"
    if any(not os.access(path, os.X_OK) for path in (*settings.values(), readelf)):
        raise ValueError(f"Android NDK is missing its API {ANDROID_API} toolchain")
    versions = {"rustc": rust["release"], "ndkRevision": ndk_revision[1], "api": ANDROID_API}
    return versions, settings, readelf


def validate_android_elf(info):
    note = re.search(r"NT_ANDROID_TYPE_IDENT[^\n]*\n\s*description data: ([0-9a-f ]+)", info)
    if (not re.search(r"^\s*Machine:\s*AArch64\s*$", info, re.MULTILINE)
            or "[Requesting program interpreter: /system/bin/linker64]" not in info
            or note is None or int.from_bytes(bytes.fromhex(note[1])[:4], "little") != ANDROID_API):
        raise ValueError(f"expected an Android API {ANDROID_API} AArch64 executable")


def build_android(args, revision, binary, receipt_path):
    versions, settings, readelf = android_toolchain(args.android_ndk)
    command = build_command(args.profile, ANDROID, args.offline)
    receipt = {"version": args.version, "gitRevision": revision, "buildCommand": command,
               "toolchain": versions}
    if args.check:
        print(json.dumps(receipt))
        return
    env = dict(os.environ, VERSION=args.version, GIT_REVISION=revision, **settings)
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    validate_android_elf(output([str(readelf), "-h", "-l", "-n", str(binary)]))
    receipt["binarySha256"] = digest(binary)
    if check_source() != revision:
        raise ValueError("checkout changed during the Android release build")
    with tempfile.NamedTemporaryFile(mode="w", dir=receipt_path.parent, delete=False) as temporary:
        json.dump(receipt, temporary, indent=2)
        temporary.write("\n")
    Path(temporary.name).replace(receipt_path)
    print(binary)


def read_report(path):
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def android_evidence(binary, args, revision, receipt_path):
    receipt = json.loads(receipt_path.read_text())
    binary_digest = digest(binary)
    if (receipt["version"] != args.version or receipt["gitRevision"] != revision
            or receipt["binarySha256"] != binary_digest or receipt["toolchain"]["api"] != ANDROID_API
            or receipt["buildCommand"] not in [build_command(ANDROID_PROFILE, ANDROID, offline)
                                                for offline in (False, True)]):
        raise ValueError("Android build receipt does not match the candidate version, source or binary")
    security, security_digest = read_report(args.android_acceptance)
    performance, performance_digest = read_report(args.android_performance)
    for report, info in ((security, security["buildInfo"]), (performance, performance["version"])):
        if report["successful"] is not True or report["binarySha256"] != binary_digest:
            raise ValueError("Android acceptance reports must pass and match the candidate binary SHA-256")
        validate_build(info, args.version, revision, ANDROID)
        if info["rust_version"] != receipt["toolchain"]["rustc"]:
            raise ValueError("Android acceptance report Rust version differs from the build receipt")
    device = security["device"]
    model, api, kernel, selinux = performance["device"]
    if model != device["model"] or int(api) != ANDROID_API or int(device["api"]) != ANDROID_API or "aarch64" not in kernel.split():
        raise ValueError(f"both reports must cover the same Android API {ANDROID_API} device model")
    if (security["configuredWorkerThreads"] != 2 or performance["parameters"]["workerThreads"] != 2
            or performance["security"]["requiredAudit"] is not True
            or performance["security"]["mode"] != "enforce"):
        raise ValueError("Android evidence must cover the two-worker Enforce and Required Audit setup")
    for protocol in ("http", "sse"):
        window = performance["soaks"][protocol]
        load = window["load"]
        audit = window["audit"]
        if (window.get("effectiveWorkerThreads") != 2
                or load["successful"] is not True or load["errors"] or load["completed"] < 1
                or load["concurrency"] != 8 or load["stream"] != (protocol == "sse")
                or load["measuredEndNs"] - load["measuredStartNs"] < 600_000_000_000
                or load["finishedNs"] < load["measuredEndNs"]
                or audit["persistenceHealthy"] is not True or audit["persistenceFailures"] != 0
                or audit["capacity"]["maximumBytes"] != ANDROID_AUDIT_BYTES
                or audit["capacity"]["retentionSeconds"] != ANDROID_RETENTION_SECONDS):
            raise ValueError(f"Android {protocol} evidence must show a successful C8 10-minute audit window")
    return security["buildInfo"], receipt["buildCommand"], {
        "binarySha256": binary_digest, "toolchain": receipt["toolchain"],
        "device": {"model": model, "api": ANDROID_API, "kernel": kernel, "selinux": selinux},
        "configuration": {"workerThreads": 2, "testedConcurrency": 8, "auditBytes": ANDROID_AUDIT_BYTES,
                          "auditRetentionSeconds": ANDROID_RETENTION_SECONDS},
        "evidence": {"securitySha256": security_digest, "performanceSha256": performance_digest},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, type=validate_version)
    parser.add_argument("--profile", required=True, choices=PROFILES)
    parser.add_argument("--output", type=Path, default=ROOT / "target/release-dist")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--check", action="store_true", help="Check source and inputs without building")
    parser.add_argument("--target", choices=("native", ANDROID), default="native")
    parser.add_argument("--android-ndk", type=Path, help="Android NDK root for the build stage")
    parser.add_argument("--build-only", action="store_true", help="Build an Android candidate for device acceptance")
    parser.add_argument("--android-acceptance", type=Path, help="Successful security report for the built Android binary")
    parser.add_argument("--android-performance", type=Path, help="Successful HTTP and SSE soak report for that binary")
    args = parser.parse_args()
    if args.target == ANDROID and args.profile != ANDROID_PROFILE:
        parser.error("the Android candidate supports the llm profile")
    android_options = (args.android_ndk, args.build_only, args.android_acceptance, args.android_performance)
    if args.target == "native" and any(android_options):
        parser.error("Android options require the Android target")
    revision = check_source()
    if args.target == ANDROID:
        binary, receipt = build_paths(ANDROID)
        if args.build_only or args.check:
            if args.android_ndk is None or args.android_acceptance or args.android_performance:
                parser.error("Android build and check require --android-ndk and do not take reports")
            build_android(args, revision, binary, receipt)
        else:
            if not args.android_acceptance or not args.android_performance:
                parser.error("Android packaging requires both device reports from the built candidate")
            info, command, evidence = android_evidence(binary, args, revision, receipt)
            print(package(binary, args.output.resolve(), args.version, args.profile, revision,
                          ANDROID, info, command, android=evidence))
        return
    target = next(line.removeprefix("host: ") for line in output(["rustc", "-vV"]).splitlines()
                  if line.startswith("host: "))
    if not target.endswith("-linux-gnu"):
        raise ValueError("this candidate packaging supports native Linux GNU builds only")
    command = build_command(args.profile, target, args.offline)
    if args.check:
        print(json.dumps({"gitRevision": revision, "buildCommand": command}))
        return
    env = dict(os.environ, VERSION=args.version, GIT_REVISION=revision)
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    binary, _ = build_paths(target)
    info = json.loads(output([str(binary), "--version"]))
    if check_source() != revision:
        raise ValueError("checkout changed during the release build")
    print(package(binary, args.output.resolve(), args.version, args.profile, revision, target, info, command))


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, TypeError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Release preparation failed: {error}") from error
