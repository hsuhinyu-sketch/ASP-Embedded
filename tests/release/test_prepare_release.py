"""Release identity, clean-source and archive checks; no production test interfaces."""

from argparse import Namespace
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prepare_release", ROOT / "scripts/prepare_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.info = {"version": "v0.1.0-rc.1", "git_revision": "a" * 40,
                     "build_profile": "release", "build_target": "x86_64-unknown-linux-gnu"}

    def test_version_cannot_inject_paths_or_shell(self):
        for value in ("../v1.0.0", "v1.0.0;pwd", "v01.0.0", "1.0.0", "v1.0.0\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release.validate_version(value)
        self.assertEqual(release.validate_version(self.info["version"]), self.info["version"])

    def test_dirty_checkout_is_rejected(self):
        with patch.object(release, "output", return_value="?? source.rs"), self.assertRaises(ValueError):
            release.check_source()

    def test_clean_checkout_has_exact_identity(self):
        with patch.object(release, "output", side_effect=["", "a" * 40]):
            self.assertEqual(release.check_source(), "a" * 40)

    def test_mismatched_binary_is_rejected(self):
        for key in self.info:
            info = dict(self.info, **{key: "wrong"})
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.validate_build(info, self.info["version"], "a" * 40,
                                       self.info["build_target"])

    def test_archive_is_minimal_and_checksum_is_verifiable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "gateway"
            binary.write_bytes(b"test executable")
            binary.chmod(0o755)
            archive = release.package(binary, root / "dist", self.info["version"], "llm",
                                      "a" * 40, self.info["build_target"], self.info, ["cargo", "build"])
            self.assertEqual(archive.with_suffix("").with_suffix(".sha256").read_text(),
                             f"{release.digest(archive)}  {archive.name}\n")
            with tarfile.open(archive) as stream:
                files = [entry for entry in stream.getmembers() if entry.isfile()]
                self.assertEqual({Path(entry.name).name for entry in files},
                                 {"ai-security-platform", "LICENSE", "Cargo.lock", "RELEASE.md",
                                  "LICENSE-platform-pool", "LICENSE-regex-cache", "manifest.json"})
                cache_license = next(entry for entry in files
                                     if entry.name.endswith("/LICENSE-regex-cache"))
                self.assertEqual(stream.extractfile(cache_license).read(),
                                 (ROOT / "crates/third-party/regex-cache/LICENSE").read_bytes())
                manifest_member = next(entry for entry in files if entry.name.endswith("/manifest.json"))
                manifest = json.load(stream.extractfile(manifest_member))
                for entry in files:
                    if entry is not manifest_member:
                        self.assertEqual(hashlib.sha256(stream.extractfile(entry).read()).hexdigest(),
                                         manifest["files"][Path(entry.name).name])
                executable = next(entry for entry in files if entry.name.endswith("/ai-security-platform"))
                self.assertTrue(executable.mode & 0o111)
            with self.assertRaises(ValueError):
                release.package(binary, root / "dist", self.info["version"], "llm",
                                "a" * 40, self.info["build_target"], self.info, ["cargo", "build"])

    def android_inputs(self, root):
        binary = root / "gateway"
        binary.write_bytes(b"Android executable fixture")
        binary.chmod(0o755)
        sha = release.digest(binary)
        info = dict(self.info, build_target=release.ANDROID, rust_version="1.96.1")
        command = release.build_command("llm", release.ANDROID, True)
        receipt = root / "build.json"
        receipt.write_text(json.dumps({"version": info["version"], "gitRevision": info["git_revision"],
                                       "binarySha256": sha, "buildCommand": command,
                                       "toolchain": {"rustc": "1.96.1", "ndkRevision": "30.0.16248370", "api": 29}}))
        args = Namespace(version=info["version"], android_acceptance=root / "security.json",
                         android_performance=root / "performance.json")
        security = {"successful": True, "binarySha256": sha, "buildInfo": info,
                    "configuredWorkerThreads": 2, "device": {"model": "test-tablet", "api": "29"}}
        audit = {"persistenceHealthy": True, "persistenceFailures": 0, "capacity": {
            "maximumBytes": release.ANDROID_AUDIT_BYTES, "retentionSeconds": release.ANDROID_RETENTION_SECONDS}}
        load = {"successful": True, "errors": [], "completed": 600, "concurrency": 8,
                "measuredStartNs": 1, "measuredEndNs": 600_000_000_001, "finishedNs": 600_000_000_002}
        performance = {"successful": True, "binarySha256": sha, "version": info,
                       "device": ["test-tablet", "29", "3.18.140 aarch64", "Permissive"],
                       "parameters": {"workerThreads": 2}, "security": {"requiredAudit": True, "mode": "enforce"},
                       "soaks": {protocol: {"effectiveWorkerThreads": 2, "audit": deepcopy(audit),
                                            "load": dict(load, stream=protocol == "sse")}
                                 for protocol in ("http", "sse")}}
        args.android_acceptance.write_text(json.dumps(security))
        args.android_performance.write_text(json.dumps(performance))
        return binary, args, receipt

    def test_android_elf_requires_api29_arm64_and_bionic_loader(self):
        output = ("  Machine: AArch64\n"
                  "[Requesting program interpreter: /system/bin/linker64]\n"
                  "Android 0x00000084 NT_ANDROID_TYPE_IDENT\n   description data: 1d 00 00 00 72 33 30\n")
        release.validate_android_elf(output)
        for old, new in (("AArch64", "x86-64"), ("/system/bin/linker64", "/lib/ld-linux-aarch64.so.1"),
                         ("1d 00 00 00", "1e 00 00 00"), ("NT_ANDROID_TYPE_IDENT", "NT_GNU_BUILD_ID")):
            with self.subTest(old=old), self.assertRaisesRegex(ValueError, "Android API 29"):
                release.validate_android_elf(output.replace(old, new))

    def test_android_requires_matching_successful_device_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, args, receipt = self.android_inputs(Path(directory))
            revision = self.info["git_revision"]
            original = json.loads(args.android_performance.read_text())
            for change in (
                lambda report: report.update(binarySha256="0" * 64),
                lambda report: report.update(successful=False),
                lambda report: report["version"].update(git_revision="a" * 40 + "-dirty"),
                lambda report: report["soaks"]["sse"].update(effectiveWorkerThreads=8),
                lambda report: report["soaks"]["http"]["load"].update(measuredEndNs=1_000_000_001),
                lambda report: report["soaks"]["http"]["load"].update(finishedNs=1),
                lambda report: report["soaks"]["http"]["audit"]["capacity"].update(maximumBytes=134217728),
                lambda report: report["soaks"]["sse"]["audit"].update(persistenceHealthy=False),
            ):
                report = deepcopy(original)
                change(report)
                args.android_performance.write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    release.android_evidence(binary, args, revision, receipt)
            args.android_performance.write_text(json.dumps(original))
            security = json.loads(args.android_acceptance.read_text())
            security["configuredWorkerThreads"] = 4
            args.android_acceptance.write_text(json.dumps(security))
            with self.assertRaisesRegex(ValueError, "two-worker"):
                release.android_evidence(binary, args, revision, receipt)

    def test_android_bundle_seals_reports_and_ships_the_rc_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, args, receipt = self.android_inputs(root)
            revision = self.info["git_revision"]
            info, command, evidence = release.android_evidence(binary, args, revision, receipt)
            with patch.object(release, "check_source", return_value=revision):
                archive = release.package(binary, root / "dist", args.version, "llm", revision,
                                          release.ANDROID, info, command, android=evidence)
            with tarfile.open(archive) as stream:
                names = {Path(entry.name).name: entry for entry in stream.getmembers() if entry.isfile()}
                manifest = json.load(stream.extractfile(names["manifest.json"]))
                self.assertEqual(manifest["android"]["binarySha256"], manifest["files"]["ai-security-platform"])
                self.assertEqual(manifest["android"]["evidence"], {
                    "securitySha256": release.digest(args.android_acceptance),
                    "performanceSha256": release.digest(args.android_performance)})
                config = stream.extractfile(names[release.ANDROID_CONFIG]).read()
                self.assertEqual(config, (ROOT / "examples/profiles" / release.ANDROID_CONFIG).read_bytes())
                self.assertNotIn("security.json", names)
                self.assertNotIn("performance.json", names)
            binary.write_bytes(b"changed after validation")
            with self.assertRaisesRegex(ValueError, "staged Android binary"):
                release.package(binary, root / "different-dist", args.version, "llm", revision,
                                release.ANDROID, info, command, android=evidence)
            with self.assertRaisesRegex(ValueError, "build receipt"):
                release.android_evidence(binary, args, revision, receipt)


if __name__ == "__main__":
    unittest.main()
