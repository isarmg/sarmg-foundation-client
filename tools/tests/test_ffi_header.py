from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
from ffi_header import generate, integer


class FfiHeaderTests(unittest.TestCase):
    def test_actual_foundation_declarations_generate_current_abi(self) -> None:
        foundation = (TOOLS.parent / "rust/crates/sarmg-mobile-ffi/src/lib.rs").read_text()
        product = 'pub unsafe extern "C" fn sample(input: *const u8, len: usize, output: *mut SarmgFfiResultV2) -> i32 { unreachable!() }'
        header = generate(foundation, product, "FIXTURE_FFI_H")
        self.assertIn("#define SARMG_FFI_ABI_REVISION 2u", header)
        self.assertIn("size_t length;", header)
        self.assertIn("int32_t sample(const uint8_t * input, size_t len, SarmgFfiResultV2 * output);", header)
        self.assertIn("sarmg_ffi_result_free_v2", header)

    def test_unsupported_types_constants_and_duplicate_exports_are_errors(self) -> None:
        source = 'pub const ABI_REVISION: u32 = 2;\npub extern "C" fn revision() -> u32 { 2 }'
        for product in [
            'pub extern "C" fn bad(input: String) -> i32 { 0 }',
            'pub extern "C" fn revision() -> u32 { 2 }',
            'pub extern "C" fn bad(input: fn(u32)) -> i32 { 0 }',
        ]:
            with self.subTest(product=product), self.assertRaises(ValueError):
                generate(source, product, "FIXTURE_H")
        for expression in ['1 << 4', '__import__("os")', '4294967296']:
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                integer(expression)
        self.assertEqual(integer("16 * 1024 * 1024"), 16777216)


if __name__ == "__main__":
    unittest.main()
