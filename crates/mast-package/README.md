## Overview

The `miden-mast-package` crate provides the `Package` type, which represents a Miden package.
It contains a compiled `Library`/`Program` along with their exported functions and dependencies.

## Binary Format

The header contains the following fields:
- "MASP" magic bytes (4 bytes);
- Version of the package binary format (3 bytes, e.g. "0.0.0");

The package data contains:
- Package name 
- MAST artifact, which is either:
  - A Program (indicated by "PRG" magic bytes)
  - A Library (indicated by "LIB" magic bytes)
- Package manifest containing:
  - List of exports, where each export has:
    - Name 
    - Digest
  - List of dependencies, where each dependency has:
    - Name  
    - Digest
- Account component metadata bytes (optional)

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
