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

SPEC = importlib.util.spec_from_file_location("check_xcsc", ROOT / "scripts/check-xcsc.py")
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class XcscBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        files = [Path("Cargo.toml"), Path("Cargo.lock"), Path("LICENSE")]
        files.extend(path.relative_to(ROOT) for directory in ["profiles", "schemas", "src"]
                     for path in (ROOT / directory).rglob("*") if path.is_file())
        for relative in files:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.root_patch = patch.object(CHECKER, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_actual_single_package_has_all_client_modules(self) -> None:
        result = CHECKER.check()
        self.assertEqual(result["packages"], ["xcsc"])
        self.assertIn("mobile_ffi", result["modules"])
        self.assertIn("log", result["modules"])

    def test_root_dependency_overrides_cannot_import_product_packages(self) -> None:
        cargo = self.root / "Cargo.toml"
        original = cargo.read_text()
        for section in [
            f'[patch.crates-io]\nproduct = {{ package = "{package}", version = "0.1" }}'
            for package in ("xcsc-product",)
        ] + [
            f'[replace]\n"{package}:0.1.0" = {{ version = "=1.0.0" }}'
            for package in ("xcsc-product",)
        ]:
            with self.subTest(section=section):
                cargo.write_text(original + "\n" + section + "\n")
                with self.assertRaisesRegex(ConformanceError, "outside client platform"):
                    CHECKER.check()

    def test_a_workspace_facade_cannot_restore_split_packages(self) -> None:
        cargo = self.root / "Cargo.toml"
        cargo.write_text(cargo.read_text() + '\n[workspace]\nmembers=["src/secret"]\n')
        with self.assertRaisesRegex(ConformanceError, "without a workspace facade"):
            CHECKER.check()

    def test_nested_cargo_package_is_forbidden(self) -> None:
        (self.root / "src/secret/Cargo.toml").write_text('[package]\nname="xcsc-secret"\nversion="1.0.0"\n')
        with self.assertRaisesRegex(ConformanceError, "independent nested Cargo"):
            CHECKER.check()

    def test_path_dependencies_are_forbidden(self) -> None:
        cargo = self.root / "Cargo.toml"
        cargo.write_text(cargo.read_text() + '\n[target.\'cfg(unix)\'.build-dependencies.local-helper]\npath="../helper"\n')
        with self.assertRaisesRegex(ConformanceError, "forbids workspace or path"):
            CHECKER.check()
