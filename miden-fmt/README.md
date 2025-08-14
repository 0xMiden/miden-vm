# Miden Assembly Code Formatter

Basic Miden Assembly code formatter.

#### Basic rules this formatter follows:
1) Adds correct indentation following the code formatting rules seen in the miden-base repository.
2) Removes trailing spaces.
3) Removes doubly empty lines.
4) Auto formats long comments by wrapping them at word boundaries (80 character limit).
5) Alphabetizes import statements.

#### Installing binary from crates
````bash
cargo install miden-fmt
````

#### Installing binary from repo:
```bash
cargo install --path .
```

#### Formatting all files in a directory:
```bash
miden-fmt /some-directory 
```

#### Formatting a single file in a directory:
```bash
miden-fmt src/asm/example3.masm
```