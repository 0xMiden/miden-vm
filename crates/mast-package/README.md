## Overview

The `miden-mast-package` crate provides the `Package` type, which represents a Miden package.
It contains a compiled `MastForest` together with package metadata, exports, runtime dependencies,
and optional custom sections.

## Binary Format

The header contains the following fields:
- `MASP\0` magic bytes;
- Version of the package binary format (currently `5.0.0`);

The package data contains:
- Package name
- Package semantic version
- Package description (optional)
- Package target kind
- MAST artifact (`MastForest`)
- Package manifest containing:
  - List of exports, where each export has:
    - Name
    - Digest
  - List of dependencies, where each dependency has:
    - Name
    - Target kind
    - Semantic version
    - Digest
- Optional custom sections, including package-owned debug sections and the embedded kernel package
  section used by executable packages

Package digests are derived from the underlying MAST artifact. Registry implementations typically
use the semantic version together with that digest as the exact published package identity.

## Debug Sections and Trust

Package-owned debug information lives in optional debug custom sections, not in the embedded
`MastForest`. Readers choose how those sections are handled:

- `Package::read_from` and `Package::read_from_bytes` are for untrusted artifacts. They validate
  the embedded MAST forest and discard package-owned debug sections before returning the package.
- `Package::read_from_trusted` and `Package::read_from_bytes_trusted` are for trusted local files
  or cache entries. They validate the embedded MAST forest and preserve package-owned debug
  sections so `Package::debug_info` can decode them.
- `Package::read_from_unchecked` and `Package::read_from_bytes_unchecked` are same-domain trusted
  cache readers. They preserve package-owned debug sections, but skip MAST validation because the
  bytes must already have been validated before persistence.

Embedded kernel package bytes are carried in the opaque `kernel` custom section. An untrusted read
may carry that section, but decoding the embedded kernel through the package API uses the
untrusted reader and strips nested debug sections before exposing the kernel package. Artifacts
serialized for consumption by an untrusted path should be produced from
`Package::without_debug_info` or after `Package::strip_debug_info`.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
