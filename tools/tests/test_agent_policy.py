from __future__ import annotations

import sys
import json
import re
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
from agent_policy import ConformanceError, verify_manifest, verify_source

VALID_MANIFEST = '''
format = 1
product_id = "fixture-product"
source_roots = ["."]
[foundation]
platform_generation = 1
version = "0.5.0"
'''

class AgentPolicyTests(unittest.TestCase):
    def test_https_consumers_cannot_depend_on_raw_reqwest_even_by_alias(self) -> None:
        manifest = VALID_MANIFEST + '\n[[components]]\nid="mobile"\nprofile="mobile-agent"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "sarmg-agent.toml").write_text(manifest)
            cargo = product / "Cargo.toml"
            for dependency in [
                '[dependencies]\nreqwest="0.13"\n',
                '[target.\'cfg(windows)\'.dependencies]\nhttp={package="reqwest",version="0.13"}\n',
                '[workspace.dependencies]\nhttp={package="reqwest",version="0.13"}\n[dependencies]\nhttp={workspace=true}\n',
            ]:
                with self.subTest(dependency=dependency):
                    cargo.write_text(dependency)
                    with self.assertRaisesRegex(ConformanceError, "secure-http-ownership"):
                        verify_source(product, ROOT)
            cargo.write_text('[dependencies]\nsarmg-agent-secure-http="=0.5.0"\n')
            verify_source(product, ROOT)

    def test_manifest_schema_accepts_the_current_version(self) -> None:
        schema = json.loads((ROOT / "schemas/sarmg-agent.schema.json").read_text())
        pattern = schema["properties"]["foundation"]["properties"]["version"]["pattern"]
        self.assertIsNotNone(re.fullmatch(pattern, "0.5.0"))
        self.assertIsNone(re.fullmatch(pattern, "0x5x0"))

    def test_server_profiles_and_dependencies_are_rejected(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-agent"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "sarmg-agent.toml"
            manifest.write_text(VALID_MANIFEST + component.replace("mobile-agent", "server-control-plane"))
            with self.assertRaisesRegex(ConformanceError, "unknown Profile"):
                verify_manifest(root, ROOT)
            manifest.write_text(VALID_MANIFEST + component)
            for dependency in [
                'sarmg-error = { path = "../sarmg-foundation-server/rust/crates/sarmg-error" }',
                'innocent = { package = "sarmg-admin-core", version = "0.5.0" }',
            ]:
                with self.subTest(dependency=dependency):
                    (root / "Cargo.toml").write_text('[package]\nname="fixture"\nversion="0.1.0"\n[dependencies]\n' + dependency)
                    with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                        verify_source(root, ROOT)
            manifest.write_text((VALID_MANIFEST + component).replace('["."]', '["../"]'))
            with self.assertRaisesRegex(ConformanceError, "escapes product"):
                verify_manifest(root, ROOT)

    def test_client_web_stays_in_client_policy(self) -> None:
        component = '\n[[components]]\nid="agent"\nprofile="desktop-agent"\ncapabilities=["private-state", "bounded-spool", "https-delivery", "doctor", "local-web-management"]\n[components.agent_limits]\nmax_record_bytes=1\nmax_spool_bytes=1\nmax_spool_entries=1\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sarmg-agent.toml").write_text(VALID_MANIFEST + component)
            source = root / "app.js"
            source.write_text("fetch('/state', {method: 'POST'});")
            self.assertEqual(verify_source(root, ROOT)["source_files"], 1)
            source.write_text("import {AdminClient} from '@sarmg/admin-web';")
            with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                verify_source(root, ROOT)

    def test_bounded_spool_limits_are_required_strict_and_cannot_exceed_profile(self) -> None:
        agent = '''
[[components]]
id = "agent"
profile = "desktop-agent"
capabilities = ["private-state", "bounded-spool", "https-delivery", "doctor"]
[components.agent_limits]
max_record_bytes = 1048576
max_spool_bytes = 268435456
max_spool_entries = 4096
'''
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            path = product / "sarmg-agent.toml"
            valid = VALID_MANIFEST + agent
            path.write_text(valid, encoding="utf-8")
            verify_manifest(product, ROOT)
            for old, new in [
                ("max_record_bytes = 1048576", "max_record_bytes = 1048577"),
                ("max_spool_bytes = 268435456", "max_spool_bytes = 268435457"),
                ("max_spool_entries = 4096", "max_spool_entries = 4097"),
                ("max_spool_entries = 4096", "max_spool_entries = true"),
                ("max_spool_entries = 4096", "max_spool_entries = 0"),
                ("max_spool_entries = 4096", "max_spool_entries = -1"),
                ("max_spool_entries = 4096", "max_spool_entries = 4.5"),
                ("max_spool_entries = 4096", "max_spool_entries = 4096\\nunknown = 1".replace("\\n", "\n")),
            ]:
                with self.subTest(new=new):
                    path.write_text(valid.replace(old, new), encoding="utf-8")
                    with self.assertRaises(ConformanceError):
                        verify_manifest(product, ROOT)
            path.write_text(VALID_MANIFEST + agent.split("[components.agent_limits]")[0], encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "requires agent_limits"):
                verify_manifest(product, ROOT)

    def test_agent_mechanisms_cannot_return_to_a_spool_consumer(self) -> None:
        manifest = VALID_MANIFEST + '''
[[components]]
id = "agent"
profile = "desktop-agent"
capabilities = ["private-state", "bounded-spool", "https-delivery", "doctor"]
[components.agent_limits]
max_record_bytes = 1048576
max_spool_bytes = 268435456
max_spool_entries = 4096
'''
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "sarmg-agent.toml").write_text(manifest, encoding="utf-8")
            source = product / "lib.rs"
            for text in [
                "fn jitter(base: Duration) {}",
                "pub fn sampling_jitter(base: Duration) {}",
                "fn retry_jitter(base: Duration) {}",
                "fn exponential_backoff(attempt: u32) {}",
                'const MAGIC: &[u8] = b"SARMGSPOOL";',
                'const LOCK: &str = "spool.instance.lock";',
                "enum FlushOutcome { Drained, BatchComplete }",
                "struct RetryBackoff { attempt: u32 }",
                "struct DeliveryWorker { backoff: u32 }",
                "struct DeliveryTrigger { sender: Sender }",
                "struct QueueFailureStreak(u32);",
                "struct CredentialSnapshot<R> { revision: R }",
                "struct AgentIdentity { instance_id: String }",
                "struct AgentSession { lock: File }",
                "struct SingleInstanceLock(File);",
                "enum CredentialAuthorization { Authorized }",
                "enum CredentialMutation { Applied, Superseded }",
                "enum FailureDisposition { Retain, Discard }",
                "enum QuarantineReason { Corrupt, IdentityMismatch }",
                "pub trait CredentialStore {}",
                "async fn deliver_batch() {}",
                "network_backoff = (network_backoff * 2).min(limit);",
            ]:
                with self.subTest(text=text):
                    source.write_text(text, encoding="utf-8")
                    with self.assertRaisesRegex(ConformanceError, "agent-runtime-ownership"):
                        verify_source(product, ROOT)
            source.write_text(
                "use sarmg_agent_runtime::retry_jitter;\n"
                "fn schedule() { retry_jitter(base, 20) }\n"
                "impl CredentialStore for HostCredentials {}\n",
                encoding="utf-8",
            )
            verify_source(product, ROOT)

    def test_mobile_ffi_mechanics_and_manual_swift_declarations_are_rejected(self) -> None:
        manifest = VALID_MANIFEST + '''
[[components]]
id = "mobile"
profile = "mobile-agent"
capabilities = ["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]
'''
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "sarmg-agent.toml").write_text(manifest)
            for suffix, text in [
                ("rs", "struct HandleRegistry {}"),
                ("rs", "fn read_c_string() {}"),
                ("rs", "fn guard_value() {}"),
                ("rs", "use std::panic::catch_unwind;"),
                ("rs", "thread_local! { static LAST_ERROR: String; }"),
                ("swift", '@_silgen_name("example") func example()'),
            ]:
                source = product / f"fixture.{suffix}"
                with self.subTest(text=text):
                    source.write_text(text)
                    with self.assertRaisesRegex(ConformanceError, "mobile-ffi-ownership"):
                        verify_source(product, ROOT)
                    source.unlink()
            (product / "lib.rs").write_text("use sarmg_mobile_ffi::{guard, HandleRegistry};")
            (product / "Agent.swift").write_text("import CurrentNativeModule")
            verify_source(product, ROOT)

    def test_tls_input_ceiling_must_come_from_foundation(self) -> None:
        manifest = VALID_MANIFEST + '''
[[components]]
id = "mobile"
profile = "mobile-agent"
capabilities = ["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]
'''
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "sarmg-agent.toml").write_text(manifest)
            source = product / "lib.rs"
            for definition in [
                "const MAX_TLS_INPUT_BYTES: usize = 999999999;",
                "struct SecureHttpClient {}", "struct ResponseBudget {}", "struct BoundedResponse {}",
                "async fn read_limited(response: Response) {}", "async fn bounded_response(response: Response) {}",
            ]:
                with self.subTest(definition=definition):
                    source.write_text(definition)
                    with self.assertRaisesRegex(ConformanceError, "secure-http-ownership"):
                        verify_source(product, ROOT)
            source.write_text("use sarmg_agent_secure_http::MAX_TLS_INPUT_BYTES;")
            verify_source(product, ROOT)
