# Miden Utils Core Derive

This crate provides procedural macros for enum dispatch patterns used throughout Miden's core utilities. It is specifically designed for the Miden VM's MAST (Merkelized Abstract Syntax Tree) node system but provides general-purpose enum dispatch functionality. It offers zero-cost enum dispatch without external dependencies, giving better control over generated code compared to alternatives like `enum_dispatch`.

## Overview

This crate replaces the external `enum_dispatch` dependency with a custom implementation that provides enum dispatch functionality for the Miden codebase. The macros automatically generate trait implementations that forward method calls to the corresponding variant's trait implementation.

## Macros

### MastNodeExt

Derives the `MastNodeExt` trait implementation for enums where each variant contains a type that implements `MastNodeExt`. This requires the `#[mast_node_ext(builder = "...")]` attribute to specify the associated builder type, and assumes each builder for the variants has an implementation of `Into` for the type specified through this attribute.

```rust
use miden_utils_core_derive::{MastNodeExt, FromVariant};

#[derive(MastNodeExt, FromVariant)]
#[mast_node_ext(builder = "MastNodeBuilder")]
pub enum MastNode {
    Block(BasicBlockNode),
    Join(JoinNode),
    Split(SplitNode),
    Loop(LoopNode),
    Call(CallNode),
    Dyn(DynNode),
    External(ExternalNode),
}
```

### MastForestContributor

Derives trait implementations that dispatch method calls to variant implementations. This requires the `#[enum_thispatch(TraitName)]` attribute to specify which trait to dispatch to.

```rust
use miden_utils_core_derive::MastForestContributor;

#[derive(MastForestContributor)]
pub enum MastNodeBuilder {
    BasicBlock(BasicBlockNodeBuilder),
    Call(CallNodeBuilder),
    Dyn(DynNodeBuilder),
    External(ExternalNodeBuilder),
    Join(JoinNodeBuilder),
    Loop(LoopNodeBuilder),
    Split(SplitNodeBuilder),
}
```

### FromVariant

Derives `From<VariantType> for EnumType` implementations for each variant in an enum where each variant contains exactly one unnamed field.

```rust
use miden_utils_core_derive::FromVariant;

#[derive(FromVariant)]
pub enum MastNode {
    Block(BasicBlockNode),
    Join(JoinNode),
    Split(SplitNode),
    // ... other variants
}
```

This generates:

```rust
impl From<BasicBlockNode> for MastNode {
    fn from(node: BasicBlockNode) -> Self {
        MastNode::Block(node)
    }
}

impl From<JoinNode> for MastNode {
    fn from(node: JoinNode) -> Self {
        MastNode::Join(node)
    }
}

// ... and so on for all variants
```

## Complete Usage Example

You can use multiple macros together to eliminate hundreds of lines of manual boilerplate:

```rust
use miden_utils_core_derive::{MastNodeExt, FromVariant, MastForestContributor};

// For the node enum
#[derive(Debug, Clone, PartialEq, Eq, MastNodeExt, FromVariant)]
#[mast_node_ext(builder = "MastNodeBuilder")]
pub enum MastNode {
    Block(BasicBlockNode),
    Join(JoinNode),
    Split(SplitNode),
    Loop(LoopNode),
    Call(CallNode),
    Dyn(DynNode),
    External(ExternalNode),
}

// For the builder enum
#[derive(Debug, MastForestContributor)]
pub enum MastNodeBuilder {
    BasicBlock(BasicBlockNodeBuilder),
    Call(CallNodeBuilder),
    Dyn(DynNodeBuilder),
    External(ExternalNodeBuilder),
    Join(JoinNodeBuilder),
    Loop(LoopNodeBuilder),
    Split(SplitNodeBuilder),
}
```

## Implementation Details

The `MastNodeExt` macro generates implementations for these methods:
- `digest()`, `before_enter()`, `after_exit()`
- `append_before_enter()`, `append_after_exit()`, `remove_decorators()`
- `to_display()`, `to_pretty_print()`
- `has_children()`, `append_children_to()`, `for_each_child()`
- `domain()`, `to_builder()`

The `MastForestContributor` macro generates implementations for:
- `add_to_forest()`
- `fingerprint_for_node()`
- `remap_children()`
- `with_before_enter()`, `with_after_exit()`
