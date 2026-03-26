# miden-format

This crate contains the `miden-format` command-line tool.

`miden-format` is currently a CST-based formatter for Miden Assembly built on the
lossless syntax tree in `miden-assembly-syntax-cst`. Its primary goals are:

- normalize the layout of structured MASM source without discarding comments
- preserve compact spellings that are part of the language syntax
- stay idempotent, so formatting already-formatted source should not introduce parse errors or
  keep moving code around on each pass

This document describes the formatter behavior as it exists today. It is intended both as user
documentation and as a maintenance reference for future changes.

## Current Defaults

These are the formatter decisions that are currently hard-coded:

| Behavior | Current default |
| --- | --- |
| Maximum line width | `80` columns |
| Structured body indentation | `4` spaces |
| Consecutive blank lines preserved | at most `1` |
| Import alias arrow spacing | `path->alias` |
| Compact error-operand instruction spacing | `assert.err=...` |
| Compact bracket-suffix instruction spacing | `push.CONST[0..2]` |

If the formatter encounters syntax errors, it reports diagnostics and does not attempt best-effort
formatting of the invalid file.

## What Gets Normalized

In general, horizontal whitespace between significant tokens is canonicalized rather than
preserved verbatim.

Current normalization rules include:

- structured bodies under `begin`, `proc`, `if`, `else`, `while`, and `repeat` are indented by
  exactly `4` spaces per nesting level
- runs of blank lines are collapsed to at most one blank line between sibling items/operations
- ordinary token spacing is normalized by syntax, for example:
  - `pub   use   miden::core::mem  ->  memory` becomes `pub use miden::core::mem->memory`
  - `pub const X=event("foo")` becomes `pub const X = event("foo")`
- line comments are trimmed at the end of the line, and then re-emitted at the formatter-chosen
  indentation level

The formatter does preserve some source choices intentionally:

- same-line groups of simple instructions are preserved when they still fit within the line width
- comments inside multiline token groups are preserved instead of being flattened away
- compact instruction spellings that are part of MASM syntax remain compact, for example:
  - `assert.err="message"`
  - `assert.err=ERR_FOO`
  - `push.SLOT[0..2]`

## Wrapping Rules

The formatter uses an `80`-column target and wraps only when the formatted single-line form would
exceed that width, or when the construct already contains comments that require multiline output.

### Imports

- `use` declarations stay on one line if they fit
- long imports wrap by path segment
- wrapped aliases are indented by `4` spaces
- import aliases always use `->alias` with no spaces around `->`

Example:

```masm
pub use ::miden::core::collections::sorted_array::lowerbound_key_value
    ->lowerbound_key_value
```

### Constants and Advice Maps

- short declarations remain on one line
- long declarations move the value expression to the next indented line
- if the value is a delimited group like `event(...)` or `[...]`, the formatter may wrap the group
  across multiple lines
- if the value expression already contains comments, the formatter keeps a multiline,
  comment-preserving layout rather than collapsing it

Example:

```masm
const VERY_LONG_EVENT =
    event(
        "miden::core::collections::sorted_array::lowerbound_key_value"
    )
```

### Type Bodies

- short single-line bodies stay inline
- long un-commented braced bodies are rewritten as one item per line
- existing multiline or commented bodies are preserved structurally and reindented

Example:

```masm
pub type VeryLongTypeName = struct {
    lower_bound_key_value: u128,
    upper_bound_key_value: u128,
}
```

### Procedure Signatures

- signatures stay on one line if they fit and contain no comments
- long signatures wrap parameters and results one item per line
- commented signatures stay multiline, and the formatter preserves those comments

Example:

```masm
pub proc println_debug_message_with_context(
    message: ptr<u8, addrspace(byte)>,
    context: ptr<u8, addrspace(byte)>
) -> (
    result: ptr<u8, addrspace(byte)>,
    status: i1
)
```

## Instruction Grouping

The formatter does not blindly force one instruction per line.

Current behavior:

- if multiple simple instructions were originally on the same line, they are allowed to remain on
  the same line
- a grouped instruction line is split only if appending the next instruction would exceed the
  `80`-column limit
- instructions are not regrouped across blank lines or standalone comments
- if an instruction has an inline trailing comment, it terminates the current same-line group
- structured operations (`if`, `while`, `repeat`) always render as their own block-oriented forms
- instructions with internal comment-bearing token groups are rendered multiline instead of being
  compacted into a flat single line

Example:

```masm
begin
    swap dup.1 add
    if.true
        nop
    end
end
```

## Comment Anchoring

Comment anchoring is line-based. The easiest way to predict where a comment will end up after
formatting is to think in terms of whether the comment is on the same line as a construct, on the
immediately following line, or separated by a blank line.

### Inline comments

A comment on the same physical line as an item, instruction, or structured header remains inline
with that construct.

Examples:

```masm
use ::miden::utils::panic # import
pub proc long_name(arg: ptr<u8, addrspace(byte)>) # proc
if.true # condition
```

These stay attached to the import, procedure header, or structured header.

### Standalone comments immediately after a node

A standalone comment on the line immediately after an item or instruction, with no blank line in
between, is treated as belonging to the preceding node.

This is the rule that preserves stack-shape comments like:

```masm
dup.4 exec.get_item_raw
# => [OLD_VALUE, VALUE, slot_ptr]
```

After formatting, that comment remains after `dup.4 exec.get_item_raw`, not before the next
instruction.

### Standalone comments before the first body operation

For structured forms such as `proc`, `begin`, `if`, `else`, `while`, and `repeat`:

- a comment on the same line as the header stays inline with the header
- a comment on its own line before the first body operation stays in the body

Example:

```masm
pub proc get_native_storage_slot_type
    # convert the index into a memory offset
    nop
end
```

The comment is preserved in the body and is not collapsed onto the `proc` header.

### Standalone comments separated by a blank line

If a standalone comment is separated from the previous node by a blank line, the formatter treats
it as leading layout for the following node instead of as a trailing comment on the previous one.

That means:

- immediate adjacency anchors backward
- a blank-line break anchors forward

### Comments inside expressions, signatures, and token groups

Comments inside multiline delimited groups are preserved in place relative to the group and then
reindented. This applies to things like:

- `event(...)` constant values
- `[...]` advice-map values
- multiline procedure signatures
- instruction token groups such as `foo(...)` or `emit.event([...])`

### Practical guidance

If you want a comment to stay attached to a specific construct:

- put it on the same line as that construct, or
- put it immediately after that construct with no intervening blank line

If you want a comment to be visually associated with the following construct:

- separate it from the previous construct with a blank line

## Hypothetical Future Configuration

`miden-format` does not currently read a configuration file. If we later introduce something like
`miden-format.toml`, the current formatter behavior maps reasonably well to the following options:

| Hypothetical option | Current value | Meaning |
| --- | --- | --- |
| `max_width` | `80` | Wrap when a formatted line would exceed this width |
| `indent_width` | `4` | Indentation level for structured bodies and wrapped continuations |
| `max_blank_lines` | `1` | Maximum number of blank lines preserved between sibling constructs |
| `preserve_single_line_instruction_groups` | `true` | Keep same-line instruction groups when they fit |
| `wrap_long_imports` | `true` | Wrap long `use` paths and aliases |
| `wrap_long_values` | `true` | Wrap long `const` and `adv_map` value expressions |
| `wrap_long_signatures` | `true` | Wrap long procedure signatures |
| `comment_anchor_mode` | `"line_based"` | Anchor comments based on same-line vs immediate-following-line placement |
| `header_comment_mode` | `"same_line_only"` | Only inline comments that appear on the same line as a structured header |
| `import_alias_spacing` | `"compact_arrow"` | Render import aliases as `path->alias` |
| `compact_instruction_err_spacing` | `"compact"` | Render error operands as `.err=...` |
| `compact_instruction_slice_spacing` | `"compact"` | Render selector/range suffixes as `op[range]` |

If we expose configuration later, these are the defaults the code implements today.

## Scope and Current Limitations

This README documents formatter behavior as implemented today, not a final stable style contract.
The formatter is still evolving, and the most likely future changes are:

- revisiting the `80`-column width policy
- exposing some of the hard-coded layout choices as configuration
- tightening documentation and tests around more edge cases in comment anchoring

Any README changes here should stay aligned with the formatter unit tests in
`crates/miden-format/src/formatter.rs`, since those tests currently serve as the most precise
executable specification of formatter behavior.
