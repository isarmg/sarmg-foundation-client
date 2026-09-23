from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from client_policy import ConformanceError

SPEC = importlib.util.spec_from_file_location("check_foundation", ROOT / "scripts/check-foundation.py")
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class FoundationBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        files = [Path("Cargo.toml"), Path("LICENSE")]
        files.extend(path.relative_to(ROOT) for directory in ["profiles", "schemas"]
                     for path in (ROOT / directory).iterdir())
        files.extend(path.relative_to(ROOT) for path in (ROOT / "rust/crates").glob("*/Cargo.toml"))
        files.extend(path.relative_to(ROOT) for path in (ROOT / "rust/crates").glob("*/LICENSE"))
        for relative in files:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.root_patch = patch.object(CHECKER, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_root_dependency_overrides_cannot_import_product_packages(self) -> None:
        cargo = self.root / "Cargo.toml"
        original = cargo.read_text()
        for section in [
            '[patch.crates-io]\nproduct = { package = "sarmg-product", version = "0.1" }',
            '[replace]\n"sarmg-product:0.1.0" = { version = "0.1.0" }',
        ]:
            with self.subTest(section=section):
                cargo.write_text(original + "\n" + section + "\n")
                with self.assertRaisesRegex(ConformanceError, "outside client platform"):
                    CHECKER.check()

    def test_workspace_dependencies_resolve_from_the_workspace_root(self) -> None:
        root_cargo = self.root / "Cargo.toml"
        original = root_cargo.read_text()
        version = CHECKER._toml(root_cargo)["workspace"]["package"]["version"]
        root_cargo.write_text(original + f'''
[workspace.dependencies.sarmg-client-secret]
path = "rust/crates/sarmg-client-secret"
version = "={version}"
''')
        member_cargo = self.root / "rust/crates/sarmg-client-secret-envelope/Cargo.toml"
        member_cargo.write_text(member_cargo.read_text().replace(
            f'{{ path = "../sarmg-client-secret", version = "={version}" }}',
            '{ workspace = true }',
        ))
        CHECKER.check()
        root_cargo.write_text(root_cargo.read_text().replace(
            'path = "rust/crates/sarmg-client-secret"',
            'path = "rust/crates/sarmg-client-error"',
        ))
        with self.assertRaisesRegex(ConformanceError, "escapes client workspace"):
            CHECKER.check()

    def test_unused_workspace_dependencies_must_stay_inside_foundation(self) -> None:
        cargo = self.root / "Cargo.toml"
        cargo.write_text(cargo.read_text() + '''
[workspace.dependencies.sarmg-product]
version = "0.1.0"
''')
        with self.assertRaisesRegex(ConformanceError, "outside client platform"):
            CHECKER.check()
