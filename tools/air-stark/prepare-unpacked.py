#!/usr/bin/env python3
"""Prepare six unpacked packages for offline checks against local unpublished support.

Requires Python 3.12+ (tomllib and tarfile data-filter extraction).
This validates shipped package inputs; it is not public-registry release verification.
The six shipped Cargo manifests and their source files remain unchanged. Only temporary
Cargo config, a copied baseline lock, and an optional processor support workspace are written.
"""
import argparse
import json
import re
import shutil
import tarfile
import tomllib
from pathlib import Path

TARGETS = ('miden-stark', 'miden-ace', 'miden-air-source', 'miden-air',
           'miden-vm-stark', 'miden-precompile-stark')

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--checkout', type=Path, default=Path.cwd())
parser.add_argument('--archives', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
checkout = args.checkout.resolve()
output = args.output.resolve()
if output == checkout or checkout in output.parents:
    raise SystemExit('--output must be outside the source checkout')
if output.exists() and (not output.is_dir() or any(output.iterdir())):
    raise SystemExit('--output must be a fresh, empty directory; stale extracted files are unsafe')
output.mkdir(parents=True, exist_ok=True)
workspace_text = (checkout / 'Cargo.toml').read_text()
workspace = tomllib.loads(workspace_text)
local = {}
versions = {}
for alias, dependency in workspace['workspace']['dependencies'].items():
    if isinstance(dependency, dict) and 'path' in dependency:
        path = (checkout / dependency['path']).resolve()
        package = tomllib.loads((path / 'Cargo.toml').read_text())['package']
        actual = package['name']
        local[actual] = path
        version = package['version']
        versions[actual] = workspace['workspace']['package']['version'] if isinstance(version, dict) else version
packaged = {}
for name in TARGETS:
    archive_path = args.archives / f'{name}-{versions[name]}.crate'
    with tarfile.open(archive_path) as archive:
        archive.extractall(output, filter='data')
    package_path = output / f'{name}-{versions[name]}'
    assert (package_path / 'Cargo.toml').is_file(), package_path
    packaged[name] = package_path

# Cargo resolves optional processor even when prover is off. Its original workspace path
# dependencies would collide with the unpacked package identities. Mirror its manifest/assets
# in a temporary support workspace and select exactly the same six unpacked package paths.
support = output / 'support-workspace'
processor = support / 'processor'
processor.mkdir(parents=True, exist_ok=True)
for entry in local['miden-processor'].iterdir():
    target = processor / entry.name
    if entry.name == 'Cargo.toml':
        shutil.copyfile(entry, target)
    elif entry.name not in ('Cargo.lock', 'target') and not target.exists():
        target.symlink_to(entry, target_is_directory=entry.is_dir())
readme = support / 'README.md'
if not readme.exists():
    readme.symlink_to(checkout / 'README.md')
text, count = re.subn(r'(\[workspace\]\s*members\s*=\s*)\[.*?\]',
                      r'\g<1>["processor"]', workspace_text, count=1, flags=re.S)
if count != 1:
    raise SystemExit('locate workspace members semantically; temporary support recipe needs adapting')
text = re.sub(r'(?m)^default-members\s*=\s*\[[^]]*\]', 'default-members = ["processor"]', text)
replacements = dict(local)
replacements.update(packaged)
replacements['miden-processor'] = processor
for alias, dependency in workspace['workspace']['dependencies'].items():
    if isinstance(dependency, dict) and 'path' in dependency:
        original = (checkout / dependency['path']).resolve()
        name = tomllib.loads((original / 'Cargo.toml').read_text())['package']['name']
        text = text.replace(json.dumps(dependency['path']), json.dumps(str(replacements[name])))
(support / 'Cargo.toml').write_text(text)
patches = dict(replacements)
for name, package_path in packaged.items():
    config = package_path / '.cargo/config.toml'
    config.parent.mkdir(exist_ok=True)
    config.write_text('[patch.crates-io]\n' + ''.join(
        json.dumps(key) + ' = { path = ' + json.dumps(str(path)) + ' }\n'
        for key, path in sorted(patches.items()) if key != name))
    shutil.copyfile(checkout / 'Cargo.lock', package_path / 'Cargo.lock')
    print(f'{name}: {package_path}')
print('All six target dependency paths point at unpacked package sources.')
print('Local supporting packages are patched explicitly; public-registry verification remains separate.')
