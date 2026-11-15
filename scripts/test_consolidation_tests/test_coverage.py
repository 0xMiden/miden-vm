"""Acceptance controls for the test-removal coverage gate."""
import copy
from pathlib import Path
import tempfile
import unittest

from test_consolidation import compare, locations, source_inventory


def report():
    return {
        "schema": 1, "complete": True, "configuration": {"seed": 0, "features": ["arbitrary"]},
        "production_sources": {"crates/field/src/word/mod.rs": "same source"},
        "locations": {
            "mapped_lines": [["word.rs", 10], ["word.rs", 11], ["word.rs", 12]],
            "covered_lines": [["word.rs", 10], ["word.rs", 11]],
            "mapped_regions": [["word.rs", 10, 1, 10, 5, 0, None],
                               ["word.rs", 11, 1, 11, 5, 0, None],
                               ["word.rs", 12, 1, 12, 5, 0, None]],
            "covered_regions": [["word.rs", 10, 1, 10, 5, 0, None],
                                ["word.rs", 11, 1, 11, 5, 0, None]],
        },
    }


class CoverageGateControls(unittest.TestCase):
    def test_unchanged_report_is_accepted(self):
        self.assertTrue(compare(report(), report())["accepted"])

    def test_covered_line_loss_is_rejected(self):
        after = report()
        after["locations"]["covered_lines"].pop()
        self.assertFalse(compare(report(), after)["accepted"])

    def test_region_loss_with_unchanged_lines_is_rejected(self):
        after = report()
        after["locations"]["covered_regions"].pop()
        self.assertFalse(compare(report(), after)["accepted"])

    def test_equal_totals_cannot_hide_swapped_coverage(self):
        after = report()
        after["locations"]["covered_lines"] = [["word.rs", 10], ["word.rs", 12]]
        self.assertFalse(compare(report(), after)["accepted"])

    def test_missing_uncovered_mapping_is_rejected(self):
        after = report()
        after["locations"]["mapped_regions"].pop()
        self.assertFalse(compare(report(), after)["accepted"])

    def test_missing_source_file_is_rejected(self):
        after = report()
        after["production_sources"] = {}
        with self.assertRaisesRegex(ValueError, "Production sources differ"):
            compare(report(), after)

    def test_incomplete_report_cannot_be_a_baseline(self):
        before = report()
        before["complete"] = False
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            compare(before, report())

    def test_missing_line_file_cannot_be_a_baseline(self):
        before = report()
        before["locations"]["mapped_regions"].append(["missing.rs", 10, 1, 10, 5, 0, None])
        with self.assertRaisesRegex(ValueError, "file inventories disagree"):
            compare(before, before)

    def test_empty_export_cannot_pass(self):
        after = report()
        after["locations"]["covered_lines"] = []
        with self.assertRaisesRegex(ValueError, "Invalid lines"):
            compare(report(), after)

    def test_seed_and_feature_drift_is_rejected(self):
        after = report()
        after["configuration"]["seed"] = 1
        with self.assertRaisesRegex(ValueError, "configurations differ"):
            compare(report(), after)

    def test_changed_production_cannot_be_compared_by_line_number(self):
        after = report()
        after["production_sources"]["crates/field/src/word/mod.rs"] = "changed"
        with self.assertRaisesRegex(ValueError, "cannot be aligned"):
            compare(report(), after)

    def test_gains_do_not_offset_losses(self):
        after = report()
        after["locations"]["covered_regions"] = after["locations"]["mapped_regions"][1:]
        result = compare(report(), after)
        self.assertEqual(len(result["lost_covered_regions"]), 1)
        self.assertEqual(len(result["gained_covered_regions"]), 1)
        self.assertFalse(result["accepted"])


class ProductionSourceControls(unittest.TestCase):
    def test_inline_tests_and_generators_are_excluded_but_production_is_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "crates/field/src/lib.rs"
            path.parent.mkdir(parents=True)
            source = ('fn production() -> u32 { 1 }\n'
                      '#[cfg(test)]\nmod checks { fn example() { assert!(true); } }\n'
                      '#[cfg(any(test, feature = "arbitrary"))]\n'
                      'mod arbitrary { fn value() -> u32 { 2 } }\n')
            path.write_text(source)
            before = source_inventory(root)
            path.write_text(source.replace('assert!(true)', 'assert!(false)').replace('{ 2 }', '{ 3 }'))
            after = source_inventory(root)
            self.assertEqual(before[path.relative_to(root).as_posix()]["production_sha256"],
                             after[path.relative_to(root).as_posix()]["production_sha256"])
            path.write_text(source.replace('{ 1 }', '{ 0 }'))
            self.assertNotEqual(before[path.relative_to(root).as_posix()]["production_sha256"],
                                source_inventory(root)[path.relative_to(root).as_posix()]["production_sha256"])

    def test_production_module_named_tests_is_not_hidden(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "crates/field/src/lib.rs"
            path.parent.mkdir(parents=True)
            path.write_text('pub mod tests { pub fn production() -> u32 { 1 } }')
            self.assertEqual(source_inventory(root)[path.relative_to(root).as_posix()]["excluded_spans"], [])

    def test_invalid_rust_stops_classification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "crates/field/src/lib.rs"
            path.parent.mkdir(parents=True)
            path.write_text('mod broken { fn unfinished(')
            with self.assertRaisesRegex(ValueError, "cannot be parsed"):
                source_inventory(root)

    def test_macro_definition_coverage_survives_test_callsite_exclusion(self):
        word, native = "crates/field/src/word/mod.rs", "crates/field/src/native/mod.rs"
        data = {"type": "llvm.coverage.json.export", "data": [{
            "files": [{"filename": name, "summary": {"lines": {"count": 1, "covered": 1}}}
                      for name in (word, native)],
            "functions": [{
                "filenames": ["crates/field/src/word/tests.rs", word, native],
                "regions": [[1, 1, 1, 8, 1, 0, 0, 0], [20, 1, 20, 8, 1, 1, 0, 0],
                            [30, 1, 30, 8, 1, 2, 0, 0], [40, 1, 40, 8, 1, 1, 0, 3]],
            }],
        }]}
        sources = {word: {"excluded_spans": []}, native: {"excluded_spans": []}}
        lcov = (f'SF:{word}\nDA:20,1\nLF:1\nLH:1\nend_of_record\n'
                f'SF:{native}\nDA:30,1\nLF:1\nLH:1\nend_of_record\n')
        result = locations(data, lcov, Path('/workspace'), sources)
        self.assertEqual(len(result["covered_regions"]), 2)
        self.assertEqual(result["covered_lines"], [(native, 30), (word, 20)])
        broken = copy.deepcopy(data)
        broken["data"][0]["files"].pop()
        with self.assertRaisesRegex(ValueError, "inventories disagree"):
            locations(broken, lcov, Path('/workspace'), sources)


class RawExportControls(unittest.TestCase):
    def setUp(self):
        self.paths = ["crates/field/src/word/mod.rs", "crates/field/src/native/mod.rs",
                      "crates/serde-utils/src/lib.rs"]
        self.sources = {name: {"excluded_spans": []} for name in self.paths}
        self.llvm = {"type": "llvm.coverage.json.export", "data": [{
            "files": [{"filename": name, "summary": {"lines": {"count": 1, "covered": 1}}}
                      for name in self.paths],
            "functions": [{"filenames": self.paths,
                           "regions": [[10, 1, 10, 8, 1, index, 0, 0] for index in range(3)]}],
        }]}
        self.records = [f'SF:{name}\nDA:10,1\nLF:1\nLH:1\nend_of_record\n' for name in self.paths]

    def parse(self, text):
        return locations(self.llvm, text, Path('/workspace'), self.sources)

    def test_missing_lcov_file_is_rejected_even_when_required_field_files_exist(self):
        with self.assertRaisesRegex(ValueError, "inventories disagree"):
            self.parse(''.join(self.records[:2]))

    def test_missing_region_file_is_rejected(self):
        self.llvm["data"][0]["functions"][0]["regions"].pop()
        with self.assertRaisesRegex(ValueError, "inventories disagree"):
            self.parse(''.join(self.records))

    def test_truncated_last_lcov_record_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no end_of_record"):
            self.parse(''.join(self.records).removesuffix('end_of_record\n'))

    def test_missing_lcov_totals_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Incomplete LCOV line totals"):
            self.parse(''.join(self.records).replace('LF:1\n', '', 1))

    def test_native_export_summary_disagreement_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "line totals disagree"):
            self.parse(''.join(self.records).replace('LF:1\n', 'LF:2\n', 1))

    def test_native_summaries_can_exceed_emitted_line_rows(self):
        # Retained native LLVM exports report totals above their DA row counts.
        # Source locations remain independent of that aggregate denominator.
        summary = self.llvm["data"][0]["files"][0]["summary"]["lines"]
        summary.update(count=2, covered=2)
        text = ''.join(self.records).replace('LF:1\nLH:1\n', 'LF:2\nLH:2\n', 1)
        result = self.parse(text)
        self.assertEqual(len(result["mapped_lines"]), 3)
