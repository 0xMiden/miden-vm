# Miden Derive Macros

This crate provides procedural macros for enums that wrap various node types.

## Macros

### MastNodeExt

Derives the `MastNodeExt` trait implementation for enums where each variant contains a type that implements `MastNodeExt`.

```rust
use miden_derive_mast_node_ext::{MastNodeExt, FromVariant};

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

### FromVariant

Derives `From<VariantType> for EnumType` implementations for each variant in an enum where each variant contains exactly one unnamed field.

```rust
use miden_derive_mast_node_ext::FromVariant;

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

## Usage

You can use both macros together to eliminate all boilerplate:

```rust
use miden_derive_mast_node_ext::{MastNodeExt, FromVariant};

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

This replaces hundreds of lines of manual boilerplate code with just a few derive attributes.