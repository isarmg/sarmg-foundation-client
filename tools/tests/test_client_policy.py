from __future__ import annotations

import sys
import json
import re
import tempfile
import subprocess
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
from client_policy import ConformanceError, verify_manifest, verify_source

VALID_MANIFEST = '''
format = 1
product_id = "fixture-product"
source_roots = ["."]
[foundation]
platform_generation = 1
version = "0.5.0"
'''

class ClientPolicyTests(unittest.TestCase):
    def test_business_library_callback_and_risk_test_panics_are_not_mobile_guards(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(VALID_MANIFEST + component)
            (product / "Cargo.toml").write_text('[package]\nname="business"\nversion="1.0.0"\n')
            (product / "src").mkdir()
            (product / "src/lib.rs").write_text(
                'unsafe extern "C" fn sqlite_callback() { std::panic::catch_unwind(|| ()); }\n'
                '#[cfg(test)] mod tests { fn interrupted_reopen() { std::panic::catch_unwind(|| panic!()); } }\n'
            )
            self.assertEqual(verify_source(product, ROOT)["status"], "verified")

    def test_exported_abi_panics_cannot_hide_in_business_named_helper_modules(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(
                VALID_MANIFEST.replace('source_roots = ["."]', 'source_roots = ["src/helpers"]') + component
            )
            (product / "src/helpers").mkdir(parents=True)
            (product / "src/helpers/guard.rs").write_text('fn translated() { std::panic::catch_unwind(|| ()); }')
            cargo = product / "Cargo.toml"
            exported = product / "src/lib.rs"
            for config, source in [
                ('[lib]\ncrate-type=["cdylib"]\n', 'mod helper;'),
                ('[lib]\ncrate-type=["staticlib"]\n', 'mod helper;'),
                ('[dependencies]\nxcsc-mobile-ffi="1.0.0"\n', 'mod helper;'),
                ('', '#[unsafe(no_mangle)] pub extern "C" fn mobile_entry() {} mod helper;'),
                ('', '#[export_name="entry"] extern "C" fn entry() {} mod helper;'),
            ]:
                with self.subTest(config=config, source=source):
                    cargo.write_text('[package]\nname="business"\nversion="1.0.0"\n' + config)
                    exported.write_text(source)
                    with self.assertRaisesRegex(ConformanceError, "mobile-ffi-ownership"):
                        verify_source(product, ROOT)

    def test_business_scoping_does_not_allow_other_redefined_mobile_mechanisms(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(VALID_MANIFEST + component)
            (product / "Cargo.toml").write_text('[package]\nname="business"\nversion="1.0.0"\n')
            source = product / "lib.rs"
            for declaration in ['struct HandleRegistry {}', 'fn read_c_string() {}', 'fn checked_c_string() {}', 'fn guard_value() {}', 'static LAST_ERROR: () = ();']:
                with self.subTest(declaration=declaration):
                    source.write_text(declaration + '\nfn risk_test() { std::panic::catch_unwind(|| ()); }')
                    with self.assertRaisesRegex(ConformanceError, "mobile-ffi-ownership"):
                        verify_source(product, ROOT)

    def test_client_packages_pin_one_declared_official_source(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(VALID_MANIFEST + component)
            cargo = product / "Cargo.toml"
            valid = 'xcsc-runtime={git="https://github.com/isarmg/xcsc.git",rev="' + 'a' * 40 + '",version="=0.5.0"}'
            cargo.write_text('[dependencies]\n' + valid)
            verify_source(product, ROOT)
            for invalid in [
                valid.replace('version="=0.5.0"', 'version="=0.4.0"'),
                valid.replace('version="=0.5.0"', 'version="0.5.0"'),
                valid.replace('rev="' + 'a' * 40 + '"', 'rev="main"'),
                valid.replace('/isarmg/', '/another-owner/'),
                'xcsc-runtime={path="../foundation"}',
                valid + '\nxcsc-secret={git="https://github.com/isarmg/xcsc.git",rev="' + 'b' * 40 + '",version="=0.5.0"}',
            ]:
                with self.subTest(requirement=invalid):
                    cargo.write_text('[dependencies]\n' + invalid)
                    with self.assertRaisesRegex(ConformanceError, "client-source-identity"):
                        verify_source(product, ROOT)

    def test_neutral_logging_is_allowed_only_as_a_pinned_leaf(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(VALID_MANIFEST + component)
            cargo = product / "Cargo.toml"
            valid = 'xcss-log = { git="https://github.com/isarmg/xcss.git", rev="' + ('a' * 40) + '", version="=1.0.0" }'
            cargo.write_text('[dependencies]\n' + valid)
            verify_source(product, ROOT)
            for invalid in [
                valid.replace('version="=1.0.0"', 'version="1.0.0"'),
                valid.replace('rev="' + ('a' * 40) + '"', 'rev="main"'),
                'xcss-log={path="../xcss/rust/crates/xcss-log"}',
                valid.replace('xcss-log', 'xcss-server-runtime'),
            ]:
                with self.subTest(dependency=invalid):
                    cargo.write_text('[dependencies]\n' + invalid)
                    with self.assertRaisesRegex(ConformanceError, 'client-boundary'):
                        verify_source(product, ROOT)

    def test_https_consumers_may_use_platform_http_clients(self) -> None:
        manifest = VALID_MANIFEST + '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(manifest)
            cargo = product / "Cargo.toml"
            for dependency in [
                '[dependencies]\nreqwest="0.13"\n',
                '[target.\'cfg(windows)\'.dependencies]\nhttp={package="reqwest",version="0.13"}\n',
                '[workspace.dependencies]\nhttp={package="reqwest",version="0.13"}\n[dependencies]\nhttp={workspace=true}\n',
            ]:
                with self.subTest(dependency=dependency):
                    cargo.write_text(dependency)
                    verify_source(product, ROOT)

    def test_dependency_checks_cannot_exclude_the_root_manifest(self) -> None:
        manifest = (VALID_MANIFEST.replace('source_roots = ["."]', 'source_roots = ["src"]')
            + '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n')
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "src").mkdir()
            (product / "src" / "lib.rs").write_text("pub fn fixture() {}")
            (product / "xcsc-client.toml").write_text(manifest)
            (product / "Cargo.toml").write_text('[dependencies]\nreqwest="0.13"\n')
            verify_source(product, ROOT)

    def test_source_root_symlink_directories_are_rejected(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            outside = product / "outside"
            outside.mkdir()
            (product / "xcsc-client.toml").write_text(VALID_MANIFEST + component)
            (product / "linked").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ConformanceError, "source symlinks"):
                verify_source(product, ROOT)

    def test_manifest_schema_accepts_the_current_version(self) -> None:
        schema = json.loads((ROOT / "schemas/xcsc-client.schema.json").read_text())
        pattern = schema["properties"]["foundation"]["properties"]["version"]["pattern"]
        self.assertIsNotNone(re.fullmatch(pattern, "0.5.0"))
        self.assertIsNone(re.fullmatch(pattern, "0x5x0"))

    def test_server_profiles_and_dependencies_are_rejected(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "xcsc-client.toml"
            manifest.write_text(VALID_MANIFEST + component.replace("mobile-client", "server-control-plane"))
            with self.assertRaisesRegex(ConformanceError, "unknown Profile"):
                verify_manifest(root, ROOT)
            manifest.write_text(VALID_MANIFEST + component)
            for dependency in [
                'xcss-error = { path = "../xcss/rust/crates/xcss-error" }',
                'innocent = { package = "xcss-admin-core", version = "0.5.0" }',
            ]:
                with self.subTest(dependency=dependency):
                    (root / "Cargo.toml").write_text('[package]\nname="fixture"\nversion="0.1.0"\n[dependencies]\n' + dependency)
                    with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                        verify_source(root, ROOT)
            manifest.write_text((VALID_MANIFEST + component).replace('["."]', '["../"]'))
            with self.assertRaisesRegex(ConformanceError, "escapes product"):
                verify_manifest(root, ROOT)

    def test_dependency_overrides_obey_the_client_boundary(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "src").mkdir()
            (product / "xcsc-client.toml").write_text(
                VALID_MANIFEST.replace('source_roots = ["."]', 'source_roots = ["src"]') + component
            )
            for dependency in [
                '[patch.crates-io]\ninnocent={package="xcss-admin-core",version="0.5.0"}',
                '[replace]\n"xcss-admin-core:0.5.0"={version="0.5.0"}',
                '[workspace.dependencies]\ninnocent={package="xcss-admin-core",version="0.5.0"}',
            ]:
                with self.subTest(dependency=dependency):
                    (product / "Cargo.toml").write_text(dependency)
                    with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                        verify_source(product, ROOT)

    def test_invalid_profile_types_produce_conformance_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            for value in ['[]', '{}', 'true', '1']:
                with self.subTest(value=value):
                    (product / "xcsc-client.toml").write_text(VALID_MANIFEST + (
                        '\n[[components]]\nid="mobile"\nprofile=' + value +
                        '\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
                    ))
                    with self.assertRaisesRegex(ConformanceError, "unknown Profile"):
                        verify_manifest(product, ROOT)

    def test_client_web_stays_in_client_policy(self) -> None:
        component = '\n[[components]]\nid="client"\nprofile="desktop-client"\ncapabilities=["private-state", "bounded-spool", "https-delivery", "doctor", "local-web-management"]\n[components.client_limits]\nmax_record_bytes=1\nmax_spool_bytes=1\nmax_spool_entries=1\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "xcsc-client.toml").write_text(VALID_MANIFEST + component)
            source = root / "app.js"
            source.write_text("fetch('/state', {method: 'POST'});")
            self.assertEqual(verify_source(root, ROOT)["source_files"], 1)
            source.write_text("import {AdminClient} from '@xcss/admin-web';")
            with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                verify_source(root, ROOT)

    def test_bounded_spool_limits_are_required_strict_and_cannot_exceed_profile(self) -> None:
        client = '''
[[components]]
id = "client"
profile = "desktop-client"
capabilities = ["private-state", "bounded-spool", "https-delivery", "doctor"]
[components.client_limits]
max_record_bytes = 1048576
max_spool_bytes = 268435456
max_spool_entries = 4096
'''
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            path = product / "xcsc-client.toml"
            valid = VALID_MANIFEST + client
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
            path.write_text(VALID_MANIFEST + client.split("[components.client_limits]")[0], encoding="utf-8")
            with self.assertRaisesRegex(ConformanceError, "requires client_limits"):
                verify_manifest(product, ROOT)

    def test_client_mechanisms_cannot_return_to_a_spool_consumer(self) -> None:
        manifest = VALID_MANIFEST + '''
[[components]]
id = "client"
profile = "desktop-client"
capabilities = ["private-state", "bounded-spool", "https-delivery", "doctor"]
[components.client_limits]
max_record_bytes = 1048576
max_spool_bytes = 268435456
max_spool_entries = 4096
'''
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(manifest, encoding="utf-8")
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
                "struct ClientIdentity { instance_id: String }",
                "struct ClientSession { lock: File }",
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
                    with self.assertRaisesRegex(ConformanceError, "client-runtime-ownership"):
                        verify_source(product, ROOT)
            source.write_text(
                "use xcsc_runtime::retry_jitter;\n"
                "fn schedule() { retry_jitter(base, 20) }\n"
                "impl CredentialStore for HostCredentials {}\n",
                encoding="utf-8",
            )
            verify_source(product, ROOT)

    def test_owning_crate_traversal_is_bounded_with_a_symlink_ancestor(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            product = root / "physical" / "product"
            product.mkdir(parents=True)
            (root / "alias").symlink_to(root / "physical", target_is_directory=True)
            (product / "xcsc-client.toml").write_text(VALID_MANIFEST + component)
            (product / "ffi.rs").write_text("use std::panic::catch_unwind;")
            code = (
                "from pathlib import Path; import sys; "
                "sys.path.insert(0, sys.argv[1]); "
                "from client_policy import verify_source; "
                "verify_source(Path(sys.argv[2]), Path(sys.argv[3]))"
            )
            result = subprocess.run(
                [sys.executable, "-c", code, str(TOOLS), str(root / "alias" / "product"), str(ROOT)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mobile-ffi-ownership", result.stderr)

    def test_mobile_ffi_mechanics_and_manual_swift_declarations_are_rejected(self) -> None:
        manifest = VALID_MANIFEST + '''
[[components]]
id = "mobile"
profile = "mobile-client"
capabilities = ["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]
'''
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(manifest)
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
            (product / "lib.rs").write_text("use xcsc_mobile_ffi::{guard, HandleRegistry};")
            (product / "Client.swift").write_text("import CurrentNativeModule")
            verify_source(product, ROOT)

    def test_https_consumers_may_own_small_transport_helpers(self) -> None:
        manifest = VALID_MANIFEST + '''
[[components]]
id = "mobile"
profile = "mobile-client"
capabilities = ["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]
'''
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(manifest)
            source = product / "lib.rs"
            for definition in [
                "const MAX_TLS_INPUT_BYTES: usize = 999999999;",
                "struct SecureHttpClient {}", "struct ResponseBudget {}", "struct BoundedResponse {}",
                "async fn read_limited(response: Response) {}", "async fn bounded_response(response: Response) {}",
            ]:
                with self.subTest(definition=definition):
                    source.write_text(definition)
                    verify_source(product, ROOT)
