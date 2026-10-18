#!/usr/bin/env python3
"""Check local package ownership and isolated native-verifier feature closure.

This reads manifests only, does not compile Rust or require a Cargo registry, and
is complementary to `cargo tree`/isolated consumer checks. It models workspace
normal/build dependencies, optional dependencies and additive feature forwarding.
"""
from __future__ import annotations

import glob
from collections import defaultdict, deque
from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {
    "miden-air-source", "miden-air", "miden-stark", "miden-ace",
    "miden-vm-stark", "miden-precompile-stark",
}
OLD = {
    "miden-lifted-air", "miden-lifted-stark", "miden-stark-transcript",
    "miden-stateful-hasher", "miden-constraint-compiler", "miden-ace-codegen",
    "miden-prover", "miden-verifier", "miden-precompiles-air",
    "miden-precompiles-prover", "miden-precompiles-verifier",
}


def read(path: Path) -> dict:
    with path.open("rb") as file:
        return tomllib.load(file)


workspace = read(ROOT / "Cargo.toml")["workspace"]
workspace_deps = workspace.get("dependencies", {})
packages: dict[str, dict] = {}
paths: dict[str, Path] = {}
errors: list[str] = []
for member in workspace["members"]:
    matches = glob.glob(str(ROOT / member))
    if not matches:
        errors.append(f"workspace member does not exist: {member}")
    for directory in matches:
        path = Path(directory) / "Cargo.toml"
        if not path.is_file():
            errors.append(f"workspace member has no Cargo.toml: {directory}")
            continue
        manifest = read(path)
        name = manifest["package"]["name"]
        packages[name] = manifest
        paths[name] = path
for name in sorted(TARGETS - packages.keys()):
    errors.append(f"missing target package: {name}")
for name in sorted(OLD & packages.keys()):
    errors.append(f"obsolete package still in workspace: {name}")


def dep_tables(manifest: dict):
    for kind in ("dependencies", "build-dependencies"):
        yield kind, manifest.get(kind, {})
    for target in manifest.get("target", {}).values():
        for kind in ("dependencies", "build-dependencies"):
            yield kind, target.get(kind, {})


def resolved(alias: str, entry: object) -> dict:
    if isinstance(entry, str):
        return {"package": alias}
    result = dict(entry)
    if result.pop("workspace", False):
        inherited = workspace_deps.get(alias, {})
        inherited = dict(inherited) if isinstance(inherited, dict) else {}
        inherited_features = inherited.get("features", [])
        result = {**inherited, **result}
        result["features"] = list(dict.fromkeys(inherited_features + result.get("features", [])))
    result.setdefault("package", alias)
    return result


deps: dict[str, dict[str, dict]] = {}
graph: dict[str, set[str]] = defaultdict(set)
for name, manifest in packages.items():
    entries: dict[str, dict] = {}
    for kind, table in dep_tables(manifest):
        for alias, entry in table.items():
            dependency = resolved(alias, entry)
            dependency["kind"] = kind
            entries[alias] = dependency
            target = dependency["package"]
            if target in packages:
                graph[name].add(target)
            if target in OLD:
                errors.append(f"{name} references obsolete dependency {target}")
    deps[name] = entries


def route(start: str, forbidden: set[str]) -> list[str] | None:
    todo = deque([(start, [start])])
    seen = {start}
    while todo:
        name, path = todo.popleft()
        for child in sorted(graph[name]):
            if child in forbidden:
                return path + [child]
            if child not in seen:
                seen.add(child)
                todo.append((child, path + [child]))
    return None


rules = {
    "miden-crypto": TARGETS,
    "miden-core": TARGETS,
    "miden-stark": TARGETS - {"miden-stark"},
    "miden-ace": {"miden-air-source", "miden-air", "miden-processor", "miden-vm-stark", "miden-precompile-stark", "miden-vm"},
    "miden-air-source": {"miden-air", "miden-vm-stark", "miden-precompile-stark", "miden-processor", "miden-vm"},
    "miden-air": {"miden-vm-stark", "miden-precompile-stark", "miden-processor", "miden-vm"},
    "miden-processor": {"miden-vm-stark", "miden-precompile-stark", "miden-vm"},
    "miden-vm-stark": {"miden-precompile-stark", "miden-vm"},
    "miden-precompile-stark": {"miden-vm-stark", "miden-vm", "miden-processor"},
}
for name, forbidden in rules.items():
    if name in packages and (found := route(name, forbidden)):
        errors.append("forbidden dependency route: " + " -> ".join(found))


def cycle(name: str, visited: set[str], stack: list[str]) -> list[str] | None:
    if name in stack:
        return stack[stack.index(name):] + [name]
    if name in visited:
        return None
    visited.add(name)
    for child in sorted(graph[name]):
        if found := cycle(child, visited, stack + [name]):
            return found
    return None


visited: set[str] = set()
for name in sorted(packages):
    if found := cycle(name, visited, []):
        errors.append("dependency cycle: " + " -> ".join(found))
        break


def closure(start: str, selected: set[str]) -> tuple[set[str], dict[str, set[str]]]:
    """Resolve additive local features with the root's default features disabled."""
    active = {start}
    features: dict[str, set[str]] = defaultdict(set)
    features[start].update(selected)
    enabled_deps: dict[str, set[str]] = defaultdict(set)
    changed = True
    while changed:
        before = (set(active), {key: set(value) for key, value in features.items()},
                  {key: set(value) for key, value in enabled_deps.items()})
        for name in list(active):
            definitions = packages[name].get("features", {})
            for feature in list(features[name]):
                for value in definitions.get(feature, []):
                    if value.startswith("dep:"):
                        enabled_deps[name].add(value[4:])
                    elif "/" in value:
                        alias, forwarded = value.split("/", 1)
                        weak = alias.endswith("?")
                        alias = alias.rstrip("?")
                        dependency = deps[name].get(alias)
                        if dependency is None:
                            continue  # External/target-irrelevant feature; Cargo validates syntax.
                        if not weak:
                            enabled_deps[name].add(alias)
                        if not weak or alias in enabled_deps[name] or not dependency.get("optional", False):
                            target = dependency["package"]
                            if target in packages:
                                features[target].add(forwarded)
                    elif value in deps[name] and value not in definitions:
                        enabled_deps[name].add(value)
                    else:
                        features[name].add(value)
            for alias, dependency in deps[name].items():
                if dependency.get("optional", False) and alias not in enabled_deps[name] and alias not in features[name]:
                    continue
                target = dependency["package"]
                if target not in packages:
                    continue
                active.add(target)
                features[target].update(dependency.get("features", []))
                if dependency.get("default-features", True):
                    features[target].add("default")
        after = (active, features, enabled_deps)
        changed = before != after
    return active, features


for name in ("miden-vm-stark", "miden-precompile-stark"):
    if name not in packages:
        continue
    for selected in (set(), {"std"}, {"std", "recursive"}):
        active, features = closure(name, selected)
        label = ",".join(sorted(selected)) or "no-default-features"
        if "miden-processor" in active:
            errors.append(f"native verifier {name}[{label}] enables processor")
        for package, feature in (("miden-stark", "capture"), ("miden-ace", "compiler"), ("miden-air-source", "tooling")):
            if feature in features[package]:
                errors.append(f"native verifier {name}[{label}] enables {package}/{feature}")

for error in errors:
    print(f"ERROR: {error}", file=sys.stderr)
if errors:
    sys.exit(1)
print(f"PASS: six target packages, {len(packages)} workspace packages, acyclic ownership routes and isolated native verifier feature closures")
