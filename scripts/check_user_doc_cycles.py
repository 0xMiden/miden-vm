#!/usr/bin/env python3
"""Check user doc cycle counts against generated core-lib docs and assembly fixtures.

Core-lib mappings in ``user-doc-cycle-mappings.toml`` must declare exactly one of:
``fixture_id`` (measured ``assembly-cycle-fixtures.toml`` case) or ``exemption``.
"""

from __future__ import annotations

import html
import re
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAPPINGS = Path(__file__).resolve().parent / "user-doc-cycle-mappings.toml"
ASSEMBLY_FIXTURES = ROOT / "processor/src/tests/assembly-cycle-fixtures.toml"


class MissingCycleTextError(ValueError):
    """Raised when a procedure description has no cycle text."""


def extract_cycles_from_description(description: str) -> str:
    description = html.unescape(description)
    matches = list(
        re.finditer(r"\bCycles(?:\s*\((estimate)\))?\s*:?\s*(.*)", description, re.DOTALL)
    )
    if not matches:
        raise MissingCycleTextError("description has no cycle text")

    match = matches[-1]
    is_estimate = match.group(1) is not None
    block = match.group(2).strip()
    block = re.split(
        r"(?:#?\s*panics\b|security:|note:)",
        block,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[0]
    block = re.sub(r"<br\s*/?>", "\n", block, flags=re.IGNORECASE)
    block = re.sub(r"</?li>", "\n", block, flags=re.IGNORECASE)
    block = re.sub(r"</?ul>", "", block, flags=re.IGNORECASE)
    block = re.sub(r"</?[^>]+>", "", block)
    block = block.replace("`", "")
    block = re.sub(r"\*\*", "", block)
    block = re.sub(r"\$([^$]+)\$", r"\1", block)
    # Preserve estimate markers (~ or Cycles (estimate)) in the normalized text.
    if "~" in block:
        is_estimate = True
    block = block.replace("~", "")
    block = re.sub(r"(?m)^\s*-\s+", "", block)
    block = re.sub(r"where:\s*", "where ", block, flags=re.IGNORECASE)
    block = re.sub(r"[,.\:;]", " ", block)
    block = re.sub(r"\s+", " ", block.lower()).strip()
    if not block:
        raise MissingCycleTextError("description has empty cycle text")
    if is_estimate:
        return f"estimate {block}"
    return block


def slice_section(content: str, section: str | None) -> str:
    if not section:
        return content

    heading = re.escape(section)
    pattern = re.compile(rf"^#{{2,3}}\s+{heading}\s*$", re.MULTILINE)
    match = pattern.search(content)
    if not match:
        raise KeyError(f"section not found: {section!r}")

    start = match.end()
    next_heading = re.search(r"^#{2,3}\s+", content[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(content)
    return content[start:end]


def extract_table_row_description(line: str, procedure: str) -> str | None:
    if not line.startswith("|") or line.startswith("| ---"):
        return None

    parts = line.split("|", 2)
    if len(parts) < 3:
        return None

    name = parts[1].split("<", 1)[0].strip()
    if name != procedure:
        return None

    description = parts[2].rstrip()
    if description.endswith("|"):
        description = description[:-1].rstrip()
    return description


def extract_user_procedure_cycles(content: str, section: str | None, procedure: str) -> str:
    scoped = slice_section(content, section)

    subsection = section or procedure
    if re.search(rf"^###\s+{re.escape(subsection)}\s*$", content, re.MULTILINE):
        for line in scoped.splitlines():
            if re.search(r"cycles", line, re.IGNORECASE):
                return extract_cycles_from_description(line)
        raise KeyError(f"no cycle text in subsection: {subsection!r}")

    for line in scoped.splitlines():
        description = extract_table_row_description(line, procedure)
        if description is not None:
            return extract_cycles_from_description(description)

    raise KeyError(f"procedure row not found: {procedure!r}")


def extract_generated_procedure_cycles(path: Path, procedure: str) -> str:
    content = path.read_text(encoding="utf-8")
    for line in content.splitlines():
        description = extract_table_row_description(line, procedure)
        if description is not None:
            return extract_cycles_from_description(description)

    raise KeyError(f"generated procedure not found: {procedure!r} in {path}")


def load_assembly_fixtures() -> dict[str, dict]:
    cases = tomllib.loads(ASSEMBLY_FIXTURES.read_text(encoding="utf-8"))["case"]
    by_id: dict[str, dict] = {}
    for case in cases:
        case_id = case["id"]
        if case_id in by_id:
            raise ValueError(f"duplicate assembly fixture id: {case_id!r}")
        by_id[case_id] = case
    return by_id


def fixture_expected_matches_cycles(fixture_expected: str, doc_cycles: str) -> bool:
    """Return True if a measured fixture expectation matches normalized doc cycle text.

    Assembly fixtures often use ``\"38 cycles\"`` while core-lib docs normalize to ``\"38\"``.
    """
    expected = fixture_expected.strip().lower()
    actual = doc_cycles.strip().lower()
    if expected == actual:
        return True
    if expected.endswith(" cycles") and expected[: -len(" cycles")] == actual:
        return True
    if actual.endswith(" cycles") and actual[: -len(" cycles")] == expected:
        return True
    return False


def check_core_lib_mappings() -> list[str]:
    entries = tomllib.loads(MAPPINGS.read_text(encoding="utf-8"))["entry"]
    fixtures = load_assembly_fixtures()
    errors: list[str] = []

    for entry in entries:
        user_path = ROOT / entry["user_doc"]
        generated_path = ROOT / entry["generated_doc"]
        section = entry.get("section")
        procedure = entry["procedure"]
        fixture_id = entry.get("fixture_id")
        exemption = entry.get("exemption")

        has_fixture = fixture_id is not None
        has_exemption = exemption is not None
        if has_fixture == has_exemption:
            errors.append(
                f"{user_path}: {procedure}: mapping must set exactly one of "
                f"`fixture_id` or `exemption` (got fixture_id={fixture_id!r}, "
                f"exemption={exemption!r})"
            )
            continue
        if has_exemption and not str(exemption).strip():
            errors.append(
                f"{user_path}: {procedure}: `exemption` must be a non-empty reason"
            )
            continue

        try:
            user_content = user_path.read_text(encoding="utf-8")
            user_cycles = extract_user_procedure_cycles(user_content, section, procedure)
            generated_cycles = extract_generated_procedure_cycles(generated_path, procedure)
        except (KeyError, MissingCycleTextError) as err:
            errors.append(
                f"{user_path}: {procedure}: {err} "
                f"(generated: {generated_path}, procedure: {procedure})"
            )
            continue

        if user_cycles != generated_cycles:
            errors.append(
                f"{user_path}: {procedure}\n"
                f"  expected (generated): {generated_cycles!r}\n"
                f"  actual (user doc):    {user_cycles!r}"
            )
            continue

        if has_exemption:
            continue

        fixture = fixtures.get(fixture_id)
        if fixture is None:
            errors.append(
                f"{user_path}: {procedure}: unknown fixture_id {fixture_id!r} "
                f"(not in {ASSEMBLY_FIXTURES.relative_to(ROOT)})"
            )
            continue

        expected = str(fixture["expected"])
        if not fixture_expected_matches_cycles(expected, user_cycles):
            errors.append(
                f"{user_path}: {procedure}: cycle text {user_cycles!r} does not match "
                f"measured fixture {fixture_id!r} expected {expected!r}"
            )

    return errors


def _normalize_table_cell(cell: str) -> str:
    text = html.unescape(cell)
    text = re.sub(r"<br\s*/?>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"</?[^>]+>", "", text)
    text = text.replace("`", "")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def table_header_cells(content: str, row_start: int) -> list[str] | None:
    """Return normalized header cells for the markdown table containing row_start."""
    prefix = content[:row_start]
    lines = prefix.splitlines()
    for idx in range(len(lines) - 1, 0, -1):
        line = lines[idx]
        if line.startswith("|") and re.search(r"^\|\s*[-:]+", line):
            header = lines[idx - 1]
            if header.startswith("|"):
                return [
                    c.strip().lower()
                    for c in header.strip().strip("|").split("|")
                ]
    return None


def _normalize_cycle_cell_text(text: str) -> str:
    text = text.lower()
    match = re.search(r"\*\(\s*(\d+\s+cycles?)\s*\)\*", text, re.IGNORECASE)
    if match:
        return re.sub(r"\s+", " ", match.group(1).lower())
    return text


def extract_cycle_cell_from_row(
    row: str,
    content: str | None = None,
    row_start: int | None = None,
) -> str | None:
    """Return the cycle cell text from a marked markdown table row.

    When the table has a Cycles column header, that column is authoritative: a blank
    cell returns None (no fallback). Otherwise fall back to an embedded
    `*(N cycles)*` fragment in the instruction cell (u32_operations).
    """
    cells = [c.strip() for c in row.strip().strip("|").split("|")]

    header_cells = None
    if content is not None and row_start is not None:
        header_cells = table_header_cells(content, row_start)

    if header_cells:
        for idx, name in enumerate(header_cells):
            if "cycle" in name:
                if idx >= len(cells):
                    return None
                text = _normalize_table_cell(cells[idx])
                if not text:
                    return None
                return _normalize_cycle_cell_text(text)

    for cell in cells:
        match = re.search(r"\*\(\s*(\d+\s+cycles?)\s*\)\*", cell, re.IGNORECASE)
        if match:
            return re.sub(r"\s+", " ", match.group(1).lower())
    return None


def check_assembly_fixtures() -> list[str]:
    cases = tomllib.loads(ASSEMBLY_FIXTURES.read_text(encoding="utf-8"))["case"]
    errors: list[str] = []

    for case in cases:
        case_id = case["id"]
        doc = case.get("doc")
        marker_name = case.get("marker")
        # Core-lib-only fixtures omit doc/marker; they are still measured by processor tests
        # and referenced from user-doc-cycle-mappings.toml via fixture_id.
        if doc is None and marker_name is None:
            continue
        if doc is None or marker_name is None:
            errors.append(
                f"fixture {case_id!r}: set both `doc` and `marker`, or omit both "
                f"for core-lib-only fixtures"
            )
            continue

        doc_path = ROOT / doc
        marker = f"<!-- cycle-check: {marker_name} -->"
        expected = case["expected"].strip().lower()

        content = doc_path.read_text(encoding="utf-8")
        if marker not in content:
            errors.append(f"{doc_path}: missing marker {marker!r}")
            continue

        marker_at = content.index(marker)
        row_start = content.rfind("\n", 0, marker_at) + 1
        row_end = content.find("\n", marker_at)
        if row_end == -1:
            row_end = len(content)
        row = content[row_start:row_end]
        actual = extract_cycle_cell_from_row(row, content, row_start)
        if actual is None:
            errors.append(
                f"{doc_path}: marker {case_id!r} row has no cycle cell matching {expected!r}"
            )
        elif actual != expected:
            errors.append(
                f"{doc_path}: marker {case_id!r} cycle cell is {actual!r}, expected {expected!r}"
            )

    return errors


def main() -> int:
    errors = check_core_lib_mappings()
    errors.extend(check_assembly_fixtures())

    if errors:
        print("User doc cycle check failed:\n", file=sys.stderr)
        for error in errors:
            print(f"- {error}\n", file=sys.stderr)
        return 1

    print("User doc cycle counts are in sync.")
    return 0


class CheckUserDocCyclesTests(unittest.TestCase):
    def test_missing_cycle_text_raises(self) -> None:
        with self.assertRaises(MissingCycleTextError):
            extract_cycles_from_description("Inputs: [a, b] Outputs: [c]")

    def test_empty_cycle_text_raises(self) -> None:
        for description in ("Cycles:", "Cycles:   ", "Cycles (estimate):", "Cycles:\n"):
            with self.subTest(description=description):
                with self.assertRaises(MissingCycleTextError):
                    extract_cycles_from_description(description)

    def test_cycle_cell_uses_cycles_column_not_operand(self) -> None:
        content = (
            "| Instruction | Stack Input | Stack Output | Cycles | Notes |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| foo | `[2, 1, ...]` | `[3, ...]` | 38 | note mentions 38 |\n"
        )
        row_start = content.index("| foo")
        row = content[row_start:content.find("\n", row_start)]
        self.assertEqual(extract_cycle_cell_from_row(row, content, row_start), "38")

    def test_blank_cycles_column_returns_none(self) -> None:
        # Present Cycles column is authoritative: do not fall back to *(38 cycles)*.
        content = (
            "| Instruction | Stack Input | Stack Output | Cycles | Notes |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| foo *(38 cycles)* | `[2, 1, ...]` | `[3, ...]` |  | note |\n"
        )
        row_start = content.index("| foo")
        row = content[row_start:content.find("\n", row_start)]
        self.assertIsNone(extract_cycle_cell_from_row(row, content, row_start))

    def test_cycle_cell_falls_back_to_embedded_cycles(self) -> None:
        row = "| u32popcnt *(38 cycles)* | [a, ...] | [b, ...] | note |"
        self.assertEqual(extract_cycle_cell_from_row(row), "38 cycles")

    def test_fixture_expected_matches_cycles(self) -> None:
        self.assertTrue(fixture_expected_matches_cycles("38", "38"))
        self.assertTrue(fixture_expected_matches_cycles("38 cycles", "38"))
        self.assertTrue(fixture_expected_matches_cycles("38", "38 cycles"))
        self.assertFalse(fixture_expected_matches_cycles("38", "32"))
        self.assertFalse(fixture_expected_matches_cycles("38 cycles", "32"))

    def test_mapping_requires_fixture_or_exemption(self) -> None:
        # Spot-check the live mappings file rather than re-implementing TOML policy here.
        entries = tomllib.loads(MAPPINGS.read_text(encoding="utf-8"))["entry"]
        self.assertGreater(len(entries), 0)
        for entry in entries:
            has_fixture = "fixture_id" in entry
            has_exemption = "exemption" in entry
            self.assertTrue(
                has_fixture != has_exemption,
                msg=f"{entry.get('procedure')}: need exactly one of fixture_id/exemption",
            )
            if has_exemption:
                self.assertTrue(str(entry["exemption"]).strip())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        unittest.main()
    else:
        sys.exit(main())
