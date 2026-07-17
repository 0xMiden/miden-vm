#!/usr/bin/env python3
"""Check user doc cycle counts against generated core-lib docs and assembly fixtures."""

from __future__ import annotations

import html
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAPPINGS = Path(__file__).resolve().parent / "user-doc-cycle-mappings.toml"
ASSEMBLY_FIXTURES = ROOT / "processor/src/tests/assembly-cycle-fixtures.toml"


def extract_cycles_from_description(description: str) -> str:
    description = html.unescape(description)
    matches = list(
        re.finditer(r"\bCycles(?:\s*\((estimate)\))?\s*:?\s*(.*)", description, re.DOTALL)
    )
    if not matches:
        return ""

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


def check_core_lib_mappings() -> list[str]:
    entries = tomllib.loads(MAPPINGS.read_text(encoding="utf-8"))["entry"]
    errors: list[str] = []

    for entry in entries:
        user_path = ROOT / entry["user_doc"]
        generated_path = ROOT / entry["generated_doc"]
        section = entry.get("section")
        procedure = entry["procedure"]

        try:
            user_content = user_path.read_text(encoding="utf-8")
            user_cycles = extract_user_procedure_cycles(user_content, section, procedure)
            generated_cycles = extract_generated_procedure_cycles(generated_path, procedure)
        except KeyError as err:
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

    return errors


def _normalize_table_cell(cell: str) -> str:
    text = html.unescape(cell)
    text = re.sub(r"<br\s*/?>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"</?[^>]+>", "", text)
    text = text.replace("`", "")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_cycle_cell_from_row(row: str) -> str | None:
    """Return the cycle cell text from a marked markdown table row.

    Prefer a dedicated Cycles column (instruction_reference style). Fall back to
    an embedded `*(N cycles)*` fragment in the instruction cell (u32_operations).
    """
    cells = [c.strip() for c in row.strip().strip("|").split("|")]
    for cell in cells:
        text = _normalize_table_cell(cell)
        if re.fullmatch(r"\d+(?: cycles?)?", text, re.IGNORECASE):
            return text.lower()
        if re.fullmatch(r"\d+(?: \d+)+", text):
            return text.lower()
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
        doc_path = ROOT / case["doc"]
        marker = f"<!-- cycle-check: {case['marker']} -->"
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
        actual = extract_cycle_cell_from_row(row)
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


if __name__ == "__main__":
    sys.exit(main())
