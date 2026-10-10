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
    @staticmethod
    def write_lock(product: Path, revision: str = "a" * 40) -> None:
        (product / "Cargo.lock").write_text(
            'version=4\n[[package]]\nname="xcsc"\nversion="0.5.0"\n'
            f'source="git+https://github.com/isarmg/xcsc.git?rev={revision}#{revision}"\n'
        )

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
                ('[dependencies]\nxcsc={version="1.0.0",features=["mobile-ffi"]}\n', 'mod helper;'),
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
            valid = 'xcsc={git="https://github.com/isarmg/xcsc.git",rev="' + 'a' * 40 + '",version="=0.5.0"}'
            cargo.write_text('[dependencies]\n' + valid)
            self.write_lock(product)
            verify_source(product, ROOT)
            for invalid in [
                valid.replace('version="=0.5.0"', 'version="=0.4.0"'),
                valid.replace('version="=0.5.0"', 'version="0.5.0"'),
                valid.replace('rev="' + 'a' * 40 + '"', 'rev="main"'),
                valid.replace('/isarmg/', '/another-owner/'),
                'xcsc={path="../client-library"}',
                valid + '\nsecond={package="xcsc",git="https://github.com/isarmg/xcsc.git",rev="' + 'b' * 40 + '",version="=0.5.0"}',
            ]:
                with self.subTest(requirement=invalid):
                    cargo.write_text('[dependencies]\n' + invalid)
                    with self.assertRaisesRegex(ConformanceError, "client-source-identity"):
                        verify_source(product, ROOT)

    def test_client_logging_cannot_import_any_server_package(self) -> None:
        component = '\n[[components]]\nid="mobile"\nprofile="mobile-client"\ncapabilities=["mobile-queue", "mobile-state", "mobile-ffi", "https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(VALID_MANIFEST + component)
            cargo = product / "Cargo.toml"
            valid = 'xcsc = { git="https://github.com/isarmg/xcsc.git", rev="' + ('a' * 40) + '", version="=0.5.0", features=["tracing"] }'
            cargo.write_text('[dependencies]\n' + valid)
            self.write_lock(product)
            verify_source(product, ROOT)
            for invalid in [
                'xcss={git="https://github.com/isarmg/xcss.git",rev="' + ('a' * 40) + '",version="=1.0.0"}',
                'logging={package="xcss",git="https://github.com/isarmg/xcss.git",rev="' + ('a' * 40) + '",version="=1.0.0"}',
                'xcss={path="../xcss"}',
                'xcss={version="=1.0.0"}',
            ]:
                with self.subTest(dependency=invalid):
                    cargo.write_text('[dependencies]\n' + invalid)
                    with self.assertRaisesRegex(ConformanceError, 'client-boundary'):
                        verify_source(product, ROOT)

    def test_resolved_graph_rejects_transitive_server_and_mismatched_client_sources(self) -> None:
        component = '\n[[components]]\nid="offline"\nprofile="offline-maintenance"\ncapabilities=["private-state", "explicit-paths", "restore-journal", "linux-openat2", "offline-sqlite-maintenance"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "xcsc-client.toml").write_text(VALID_MANIFEST + component)
            (product / "Cargo.toml").write_text('[dependencies]\nxcsc={git="https://github.com/isarmg/xcsc.git",rev="' + 'a' * 40 + '",version="=0.5.0",features=["offline-maintenance"]}')
            with self.assertRaisesRegex(ConformanceError, "requires a resolved Cargo.lock"):
                verify_source(product, ROOT)
            self.write_lock(product)
            verify_source(product, ROOT)
            original = (product / "Cargo.lock").read_text()
            for package in ('xcss', 'xcss-log', 'xcsc-runtime'):
                with self.subTest(package=package):
                    (product / "Cargo.lock").write_text(original + f'[[package]]\nname="{package}"\nversion="1.0.0"\n')
                    with self.assertRaises(ConformanceError):
                        verify_source(product, ROOT)
            self.write_lock(product, "b" * 40)
            with self.assertRaisesRegex(ConformanceError, "resolved xcsc differs"):
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

    def test_canonical_server_ids_cannot_claim_a_client_profile(self) -> None:
        component = '\n[[components]]\nid="cli"\nprofile="desktop-client"\ncapabilities=["https-delivery"]\n'
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            manifest = product / "xcsc-client.toml"
            for identifier in ("xczs", "xsos", "xscs", "xszs", "xcos", "xocs", "xcss", "xabs"):
                with self.subTest(server=identifier):
                    manifest.write_text(VALID_MANIFEST.replace("fixture-product", identifier) + component)
                    with self.assertRaisesRegex(ConformanceError, "client-role"):
                        verify_manifest(product, ROOT)
            for identifier in ("xsoc", "xscc", "xszc", "xcoc", "xssc", "xcsc", "fixture-product"):
                with self.subTest(client=identifier):
                    manifest.write_text(VALID_MANIFEST.replace("fixture-product", identifier) + component)
                    self.assertEqual(verify_manifest(product, ROOT)["product_id"], identifier)

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
            (root / "xcsc-client.toml").write_text(
                VALID_MANIFEST.replace("fixture-product", "xscc").replace("0.5.0", "1.0.0") + component
            )
            source = root / "app.js"
            source.write_text("fetch('/state', {method: 'POST'});")
            self.assertEqual(verify_source(root, ROOT)["source_files"], 1)
            source.write_text("import {AdminClient} from '@xcss/web/admin-web';")
            with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                verify_source(root, ROOT)

    @staticmethod
    def write_web_client_manifest(product: Path, source_directory: str = ".") -> None:
        component = '\n[[components]]\nid="client"\nprofile="desktop-client"\ncapabilities=["private-state", "bounded-spool", "https-delivery", "doctor", "local-web-management"]\n[components.client_limits]\nmax_record_bytes=1\nmax_spool_bytes=1\nmax_spool_entries=1\n'
        manifest = (VALID_MANIFEST.replace("fixture-product", "xscc")
            .replace("0.5.0", "1.0.0")
            .replace('source_roots = ["."]', f'source_roots = ["{source_directory}"]'))
        (product / "xcsc-client.toml").write_text(manifest + component)

    def test_single_server_web_package_and_every_subpath_are_rejected(self) -> None:
        specifiers = ["@xcss/web"] + [f"@xcss/web/{module}" for module in (
            "admin-web", "admin-shell", "admin-ui", "contracts", "design-tokens",
            "http-client", "web-fonts", "web-toolchain", "contracts/schemas/state",
            "future-module/deep/path",
        )]
        imports = (
            "import {{AdminClient}} from '{specifier}';",
            "import '{specifier}';",
            "export * from '{specifier}';",
            "const server = require('{specifier}');",
            "const server = import('{specifier}');",
        )
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            self.write_web_client_manifest(product)
            source = product / "app.js"
            for specifier in specifiers:
                for statement in imports:
                    with self.subTest(specifier=specifier, statement=statement):
                        source.write_text(statement.format(specifier=specifier))
                        with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                            verify_source(product, ROOT)

    def test_server_web_imports_are_checked_in_all_javascript_source_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            self.write_web_client_manifest(product)
            for extension in ("js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx", "html"):
                with self.subTest(extension=extension):
                    source = product / f"app.{extension}"
                    source.write_text("import '@xcss/web/admin-shell';")
                    try:
                        with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                            verify_source(product, ROOT)
                    finally:
                        source.unlink()

    def test_retired_server_web_packages_and_client_aliases_are_rejected(self) -> None:
        retired = (
            "admin-web", "admin-shell", "admin-ui", "contracts", "design-tokens",
            "http-client", "web-fonts", "web-toolchain", "client-state", "client-web",
        )
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            self.write_web_client_manifest(product)
            source = product / "app.js"
            for package in retired:
                with self.subTest(package=package):
                    source.write_text(f"import '@xcss/{package}';")
                    with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                        verify_source(product, ROOT)

    def test_all_dependency_sections_reject_server_web_and_retired_client_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            self.write_web_client_manifest(product)
            package = product / "package.json"
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for dependency in ("@xcss/web", "@xcss/client-web", "@xcss/client-state"):
                    with self.subTest(section=section, dependency=dependency):
                        package.write_text(json.dumps({section: {dependency: "1.0.0"}}))
                        with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                            verify_source(product, ROOT)

    def test_npm_aliases_cannot_hide_the_server_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            self.write_web_client_manifest(product)
            package = product / "package.json"
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for target in ("@xcss/web", "@xcss/client-web"):
                    with self.subTest(section=section, target=target):
                        package.write_text(json.dumps({section: {"local-ui": f"npm:{target}@1.0.0"}}))
                        with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                            verify_source(product, ROOT)

    def test_source_roots_cannot_exclude_root_or_nested_server_web_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            (product / "src").mkdir()
            (product / "workspace-ui").mkdir()
            (product / "src/app.js").write_text("fetch('/state');")
            self.write_web_client_manifest(product, "src")
            for relative in ("package.json", "workspace-ui/package.json"):
                with self.subTest(path=relative):
                    package = product / relative
                    package.write_text(json.dumps({"dependencies": {"@xcss/web": "1.0.0"}}))
                    try:
                        with self.assertRaisesRegex(ConformanceError, "client-boundary"):
                            verify_source(product, ROOT)
                    finally:
                        package.unlink()

    def test_third_party_packages_and_local_client_web_remain_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            self.write_web_client_manifest(product)
            source = product / "app.tsx"
            source.write_text(
                "import React from 'react';\n"
                "import '@xcss-community/web';\n"
                "import '@other/xcss';\n"
                "import './web/admin-shell';\n"
                "fetch('/state', {method: 'POST'});\n"
            )
            (product / "package.json").write_text(json.dumps({
                "dependencies": {"react": "19.2.3", "@xcss-community/web": "1.0.0", "@other/xcss": "1.0.0"},
                "devDependencies": {"local-ts": "npm:typescript@7.0.2"},
            }))
            self.assertEqual(verify_source(product, ROOT)["source_files"], 1)

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
                "use xcsc::runtime::retry_jitter;\n"
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
            (product / "lib.rs").write_text("use xcsc::mobile_ffi::{guard, HandleRegistry};")
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
