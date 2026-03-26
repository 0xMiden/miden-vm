#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import re
import shutil
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
UNRELEASED_DIR = ROOT / ".changes" / "unreleased"
ARCHIVE_DIR = ROOT / ".changes" / "archive"
SECTION_ORDER = ["enhancement", "change", "fix"]
SECTION_HEADERS = {
    "enhancement": "Enhancements",
    "change": "Changes",
    "fix": "Fixes",
}


class FragmentError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch changelog fragments into CHANGELOG.md and archive them."
    )
    parser.add_argument("--version", required=True, help="Release version, e.g. 0.23.0")
    parser.add_argument(
        "--date",
        default=dt.date.today().isoformat(),
        help="Release date in YYYY-MM-DD format",
    )
    return parser.parse_args()


def parse_fragment(path: pathlib.Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    if len(lines) < 4 or lines[0] != "---":
        raise FragmentError(f"{path} must start with YAML front matter delimited by '---'")

    try:
        closing = lines.index("---", 1)
    except ValueError as exc:
        raise FragmentError(f"{path} is missing the closing front matter delimiter") from exc

    front_matter: dict[str, str] = {}
    for line in lines[1:closing]:
        if not line.strip():
            continue
        if ":" not in line:
            raise FragmentError(f"{path} has invalid front matter line: {line}")
        key, value = line.split(":", 1)
        front_matter[key.strip()] = value.strip()

    kind = front_matter.get("kind", "")
    if kind not in {"breaking", "change", "enhancement", "fix"}:
        raise FragmentError(f"{path} has invalid kind '{kind}'")

    pr_url = front_matter.get("pr", "")
    if not re.match(r"^https://github\.com/[^/]+/[^/]+/pull/\d+$", pr_url):
        raise FragmentError(f"{path} has invalid PR URL '{pr_url}'")

    crate = front_matter.get("crate", "")
    if crate and not re.match(r"^[a-z0-9][a-z0-9-]*$", crate):
        raise FragmentError(f"{path} has invalid crate '{crate}'")

    body = "\n".join(lines[closing + 1 :]).strip()
    if not body:
        raise FragmentError(f"{path} must have a non-empty summary body")

    pr_number = int(pr_url.rstrip("/").split("/")[-1])
    return {
        "path": str(path),
        "filename": path.name,
        "kind": kind,
        "pr_url": pr_url,
        "crate": crate,
        "body": body,
        "pr_number": pr_number,
    }


def normalize_summary(text: str) -> str:
    return " ".join(text.split())


def make_bullet(fragment: dict[str, str]) -> tuple[str, str]:
    kind = fragment["kind"]
    section = "change" if kind == "breaking" else kind
    summary = normalize_summary(fragment["body"])
    if kind == "breaking" and not summary.startswith("[BREAKING]"):
        summary = f"[BREAKING] {summary}"
    if fragment["crate"]:
        summary = f"**{fragment['crate']}**: {summary}"
    summary = summary.rstrip(".")
    pr_number = fragment["pr_number"]
    pr_url = fragment["pr_url"]
    return section, f"- {summary} ([#{pr_number}]({pr_url}))."


def collect_fragments() -> list[dict[str, str]]:
    paths = sorted(UNRELEASED_DIR.glob("*.md"))
    if not paths:
        raise FragmentError(f"No fragments found in {UNRELEASED_DIR}")
    fragments = [parse_fragment(path) for path in paths]
    fragments.sort(key=lambda item: (item["pr_number"], item["filename"]))
    return fragments


def build_generated_sections(fragments: list[dict[str, str]]) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {key: [] for key in SECTION_ORDER}
    for fragment in fragments:
        section, bullet = make_bullet(fragment)
        sections[section].append(bullet)
    return sections


def split_version_sections(changelog: str, version: str) -> tuple[str, str | None, str]:
    pattern = re.compile(
        rf"^## (?P<prefix>v?){re.escape(version)} \((?P<date>[^)]+)\)\s*$",
        re.MULTILINE,
    )
    match = pattern.search(changelog)
    if not match:
        return changelog, None, ""

    start = match.start()
    next_match = re.compile(r"^## ", re.MULTILINE).search(changelog, match.end())
    end = next_match.start() if next_match else len(changelog)
    return changelog[:start], changelog[start:end], changelog[end:]


def insert_bullets(section_text: str, header: str, bullets: list[str]) -> str:
    if not bullets:
        return section_text

    alias_pattern = re.compile(
        rf"^#### (?P<header>{re.escape(header)}|Bug Fixes)\s*$" if header == "Fixes" else rf"^#### (?P<header>{re.escape(header)})\s*$",
        re.MULTILINE,
    )
    match = alias_pattern.search(section_text)
    block = "\n".join(bullets) + "\n"

    if match:
        insert_at = match.end()
        next_heading = re.compile(r"^#### ", re.MULTILINE).search(section_text, insert_at)
        end = next_heading.start() if next_heading else len(section_text)
        existing_block = section_text[insert_at:end]
        if existing_block and not existing_block.startswith("\n"):
            block = "\n" + block
        return section_text[:end] + block + section_text[end:]

    suffix = section_text.rstrip()
    if suffix:
        suffix += "\n\n"
    suffix += f"#### {header}\n\n" + "\n".join(bullets) + "\n"
    return suffix + "\n"


def update_existing_section(existing: str, version: str, date: str, generated: dict[str, list[str]]) -> str:
    heading_pattern = re.compile(
        rf"^(## (?P<prefix>v?){re.escape(version)}) \((?P<date>[^)]+)\)\s*$",
        re.MULTILINE,
    )
    match = heading_pattern.search(existing)
    if not match:
        raise FragmentError(f"Could not find the {version} section heading to update")

    prefix = match.group("prefix")
    updated = heading_pattern.sub(rf"## {prefix}{version} ({date})", existing, count=1)
    for key in SECTION_ORDER:
        updated = insert_bullets(updated, SECTION_HEADERS[key], generated[key])
    return updated.rstrip() + "\n\n"


def create_new_section(version: str, date: str, generated: dict[str, list[str]]) -> str:
    lines = [f"## {version} ({date})", ""]
    for key in SECTION_ORDER:
        bullets = generated[key]
        if not bullets:
            continue
        lines.append(f"#### {SECTION_HEADERS[key]}")
        lines.append("")
        lines.extend(bullets)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n\n"


def update_changelog(version: str, date: str, generated: dict[str, list[str]]) -> None:
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")
    before, existing, after = split_version_sections(changelog, version)

    if existing is not None:
        updated_section = update_existing_section(existing, version, date, generated)
        new_changelog = before + updated_section + after.lstrip("\n")
    else:
        header_match = re.match(r"^# Changelog\s*\n+", changelog)
        if not header_match:
            raise FragmentError(f"{CHANGELOG_PATH} must start with '# Changelog'")
        new_section = create_new_section(version, date, generated)
        new_changelog = changelog[: header_match.end()] + new_section + changelog[header_match.end() :]

    CHANGELOG_PATH.write_text(new_changelog, encoding="utf-8")


def archive_fragments(version: str, fragments: list[dict[str, str]]) -> None:
    destination = ARCHIVE_DIR / version
    destination.mkdir(parents=True, exist_ok=True)

    for fragment in fragments:
        source = pathlib.Path(fragment["path"])
        target = destination / source.name
        if target.exists():
            raise FragmentError(f"Archive target already exists: {target}")
        shutil.move(str(source), str(target))


def main() -> int:
    args = parse_args()
    try:
        fragments = collect_fragments()
        generated = build_generated_sections(fragments)
        update_changelog(args.version, args.date, generated)
        archive_fragments(args.version, fragments)
    except FragmentError as exc:
        print(exc, file=sys.stderr)
        return 1

    print(f"Prepared changelog release for {args.version} using {len(fragments)} fragment(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
