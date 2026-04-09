## Overview

The `miden-mast-package` crate provides the `Package` type, which represents a Miden package.
It contains a compiled `Library`/`Program` together with package metadata, exports, runtime
dependencies, and optional custom sections.

## Binary Format

The header contains the following fields:
- `MASP\0` magic bytes;
- Version of the package binary format (currently `4.0.0`);

The package data contains:
- Package name
- Package semantic version
- Package description (optional)
- Package target kind
- MAST artifact, which is either:
  - A Program (indicated by "PRG" magic bytes)
  - A Library (indicated by "LIB" magic bytes)
- Package manifest containing:
  - List of exports, where each export has:
    - Name
    - Digest
  - List of dependencies, where each dependency has:
    - Name
    - Target kind
    - Semantic version
    - Digest
- Optional custom sections

Package digests are derived from the underlying MAST artifact. Registry implementations typically
use the semantic version together with that digest as the exact published package identity.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
