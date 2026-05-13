# miden-assembly-syntax

This crate provides parsing and semantic analysis of the Miden Assembly language.

## Developer guide

The following sections will guide you through how to make some of the more 
common syntax changes that come up from time to time. Syntax parsing and
analysis is split between this crate and `miden-assembly-syntax-cst`, where
the latter contains the _concrete syntax tree_ (represents what was literally
written by a user in source code), while this crate contains the _abstract
syntax tree_ (the form we perform semantic analysis and assembly on), as well
as tools for lowering the CST to AST, and performing semantic analysis.

## Adding new instructions

One of the more common tasks you may need to perform is adding support for a
new instruction. This is done as follows:

1. Add a new variant to the `Instruction` enum in this crate
2. Add support for assembling this new variant in `crates/assembly/src/instruction/mod.rs`
3. Add support for parsing the new instruction from the CST in `parser/cst/instructions.mod`
  a. If the instruction is a new simple primitive instruction, add a new entry to `PRIMITIVE_SPECS`
  b. If the instruction accepts an immediate value, add a new entry to `COMPACT_SUFFIX_SPECS`. Try and make use of one of the existing patterns, but if a new one is needed, you'll need to add a new `CompactSuffixKind` variant to represent the pattern, and implement a new lowering function for that variant.
  c. For any other instruction, a new entry must be added to `EXTENDED_INSTRUCTION_SPECS`. You'll likely need to add a new `ExtendedInstructionKind` variant as well, unless you are adding a new variation on one of the existing patterns. New variants of that enum require a corresponding lowering function as well.
4. Add tests to make sure that you get the desired AST given the MASM syntax you wish to support.

## Deprecating instructions

Removing instructions typically requires a deprecation period, so this section is presumed to be a prelude to later removing the same instruction. If you wish to just remove the instruction with no deprecation, you can skip this section.

If the instruction is being renamed, you can deprecate the old alias and automatically replace it with the new name by adding an entry to `DEPRECATED_ALIAS_SPECS`

For other forms of deprecation, we have not yet added infrastructure for it, but the best place to add new types of deprecation handling is in `try_lower_instruction`, which is where the existing deprecation handling lives.

## Removing instructions

After deprecating an instruction, removing an instruction is straightforward:

* Remove the variant from the `Instruction` enum in this crate
* Remove the lowering code from the `parser::cst` module in this crate
* Remove any references in existing tests or MASM sources
* Remove any dead code that results from the above changes

## Adding new top-level forms

This document will not go into deep detail on this topic, as new forms are typically accompanied by new syntax that may require modifications to parser machinery that is not typically touched for routine changes.

However, to provide some orientation for those that may find themselves needing to do so, a few pointers to help you decide how best to tackle this:

* To start with, is the syntax of the new form unambiguous? You must ensure that it can be unambiguously parsed, or it can cause weird edge cases to crop up. For example, you should attempt to avoid left-recursive non-terminal rules where possible, as it can make it impossible to determine whether to produce a node, or keep consuming more tokens. In general, prefer to have some form of explicit terminator token for top-level forms, rather than relying on implicit termination by encountering the start of some other top-level item - this is often unreliable, and makes it more difficult to detect subtle syntax mistakes.
* Once you know what the syntax will be, the next step is to define the AST node(s) corresponding to that syntax. Take a look at existing AST nodes for reference, if you are unsure how to structure them.
* Next, you will need to support parsing the new syntax into CST, and then implement support for lowering the new CST syntax to the AST node(s) you created. The exact details of this are highly dependent on the specific syntax, and how much of it is brand new, versus how much of the existing machinery can be used for the new form.
  a. Does the new form require tokens that are not currently valid in MASM? For example, some new punctuation, or a sigil that needs special recognition. If so, you will need to add a new `SyntaxKind` variant, a new `Token` variant, and modify the lexer (all in `miden-assembly-syntax-cst`), in order to even be able to parse a source file containing the new token. Next, you will generally need to modify the CST parser in `miden-assembly-syntax-cst` to handle the new token/syntax kind type in existing parser rules. From there, you can move on to parsing the form itself.
  b. Is the new form largely a duplicate of an existing form, just with minor differences? If so, you may find it easiest to simply duplicate the existing parser logic for that form, and modify it as appropriate. The specific details depend on the form.

Ultimately, the CST -> AST lowering lives in `crates/assembly-syntax/src/parser/cst`, in `forms.rs` and `fragments.rs`. Depending on how much new syntax there is, you may find it necessary to modify the parser itself in new ways - if so, make sure you update this document as appropriate.


## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
