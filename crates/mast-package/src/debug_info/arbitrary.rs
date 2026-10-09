use alloc::vec;
use core::num::NonZeroU32;

use miden_assembly_syntax::ast::DebugVarLocation;
use miden_core::Word;
use miden_debug_types::{ByteIndex, ColumnNumber, LineNumber};
use proptest::prelude::*;

use super::*;

impl Arbitrary for PackageDebugInfo {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_params: Self::Parameters) -> Self::Strategy {
        (
            any::<[u32; 4]>(),
            any::<[u32; 4]>(),
            any::<MastNodeId>(),
            any::<MastNodeId>(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<u64>(),
            any::<u8>(),
            any::<u8>(),
        )
            .prop_map(
                |(
                    mast_root_a,
                    mast_root_b,
                    exec_node_a,
                    exec_node_b,
                    checksum_a,
                    checksum_b,
                    error_code,
                    cycles_a,
                    cycles_b,
                )| {
                    let mut builder = PackageDebugInfoBuilder::default();

                    // Populate tables in dependency order so that every index stored below is
                    // valid in the completed debug info.
                    let file_a = builder
                        .add_file(Uri::new("file:///arbitrary/source-a.masm"), Some(checksum_a));
                    let file_b = builder
                        .add_file(Uri::new("file:///arbitrary/source-b.masm"), Some(checksum_b));
                    let location_a = builder.add_location_info(DebugLoc {
                        file_idx: file_a,
                        start: ByteIndex::new(0),
                        end: ByteIndex::new(1),
                    });
                    let location_b = builder.add_location_info(DebugLoc {
                        file_idx: file_b,
                        start: ByteIndex::new(1),
                        end: ByteIndex::new(2),
                    });

                    let primitive_type =
                        builder.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32));
                    let function_type = builder.add_type(DebugTypeInfo::Function {
                        return_type_idx: Some(primitive_type),
                        param_type_indices: vec![primitive_type],
                    });

                    let context_a = builder.add_string("arbitrary::context-a");
                    let context_b = builder.add_string("arbitrary::context-b");
                    let op_a = builder.add_string("op-a");
                    let op_b = builder.add_string("op-b");
                    let variable_a = builder.add_string("variable-a");
                    let variable_b = builder.add_string("variable-b");
                    let function_name_a = builder.add_string("function-a");
                    let function_name_b = builder.add_string("function-b");
                    let linkage_name_a = builder.add_string("linkage-a");
                    let linkage_name_b = builder.add_string("linkage-b");

                    // Functions and inline-call rows refer to each other through source and
                    // function indices. Build the source nodes first, then attach inline calls
                    // once the function table has been populated.
                    let source_a = builder
                        .add_node(DebugSourceNode {
                            exec_node: exec_node_a,
                            children: vec![],
                            op_start: 0,
                            op_end: 2,
                            asm_ops: vec![DebugSourceAsmOp::new(
                                0,
                                Some(location_a),
                                context_a,
                                op_a,
                                cycles_a.max(1),
                            )],
                            debug_vars: vec![DebugSourceVar {
                                op_idx: 0,
                                name_idx: variable_a,
                                type_id: Some(primitive_type),
                                arg_idx: Some(NonZeroU32::new(1).unwrap()),
                                location_idx: Some(location_a),
                                value_location: DebugVarLocation::Stack(0),
                            }],
                            inline_calls: vec![],
                        })
                        .expect("two arbitrary source nodes fit in the source table");
                    let source_b = builder
                        .add_node(DebugSourceNode {
                            exec_node: exec_node_b,
                            children: vec![source_a],
                            op_start: 0,
                            op_end: 2,
                            asm_ops: vec![DebugSourceAsmOp::new(
                                0,
                                Some(location_b),
                                context_b,
                                op_b,
                                cycles_b.max(1),
                            )],
                            debug_vars: vec![DebugSourceVar {
                                op_idx: 0,
                                name_idx: variable_b,
                                type_id: Some(function_type),
                                arg_idx: None,
                                location_idx: Some(location_b),
                                value_location: DebugVarLocation::Memory(error_code as u32),
                            }],
                            inline_calls: vec![],
                        })
                        .expect("two arbitrary source nodes fit in the source table");

                    let function_a = builder.add_function(
                        DebugFunctionInfo::new(
                            Some(source_a),
                            function_name_a,
                            file_a,
                            LineNumber::new(1).unwrap(),
                            ColumnNumber::new(1).unwrap(),
                            Word::from(mast_root_a),
                        )
                        .with_linkage_name(linkage_name_a)
                        .with_type(function_type),
                    );
                    let function_b = builder.add_function(
                        DebugFunctionInfo::new(
                            Some(source_b),
                            function_name_b,
                            file_b,
                            LineNumber::new(2).unwrap(),
                            ColumnNumber::new(2).unwrap(),
                            Word::from(mast_root_b),
                        )
                        .with_linkage_name(linkage_name_b)
                        .with_type(function_type),
                    );

                    builder[source_a].inline_calls.push(DebugSourceInlineCall {
                        op_idx: 1,
                        callee_idx: function_b,
                        loc_idx: location_a,
                    });
                    builder[source_b].inline_calls.push(DebugSourceInlineCall {
                        op_idx: 1,
                        callee_idx: function_a,
                        loc_idx: location_b,
                    });
                    builder.add_root(source_a);
                    builder.add_root(source_b);

                    builder.add_error_message(error_code, Arc::from("arbitrary error message a"));
                    builder.add_error_message(
                        error_code.wrapping_add(1),
                        Arc::from("arbitrary error message b"),
                    );

                    *builder.build()
                },
            )
            .boxed()
    }
}

// ARBITRARY FOR INDEX NEWTYPES AND LEAF ROWS
// ================================================================================================

macro_rules! impl_arbitrary_id {
    ($name:ty) => {
        impl Arbitrary for $name {
            type Parameters = ();
            type Strategy = BoxedStrategy<Self>;

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                // Any u32 is a valid table index on the wire; the edge-biased mix hits the 0
                // and u32::MAX bounds that flat sampling would never reach.
                prop_oneof![Just(0u32), Just(u32::MAX), any::<u32>()]
                    .prop_map(Self::from)
                    .boxed()
            }
        }
    };
}

impl_arbitrary_id!(DebugStringIdx);
impl_arbitrary_id!(DebugTypeIdx);
impl_arbitrary_id!(DebugFileIdx);
impl_arbitrary_id!(DebugFunctionIdx);
impl_arbitrary_id!(DebugLocIdx);
impl_arbitrary_id!(DebugSourceNodeId);

impl Arbitrary for DebugFieldInfo {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Flat row of any-valid fields: string/type table indices and a byte offset.
        (any::<DebugStringIdx>(), any::<DebugTypeIdx>(), any::<u32>())
            .prop_map(|(name_idx, type_idx, offset)| Self { name_idx, type_idx, offset })
            .boxed()
    }
}

impl Arbitrary for DebugVariantInfo {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Options are any-valid on the wire (independent bools); the discriminant is a full
        // u128 written as hi/lo halves.
        (
            any::<DebugStringIdx>(),
            any::<Option<DebugTypeIdx>>(),
            any::<Option<u32>>(),
            any::<u128>(),
        )
            .prop_map(|(name_idx, type_idx, payload_offset, discriminant)| Self {
                name_idx,
                type_idx,
                payload_offset,
                discriminant,
            })
            .boxed()
    }
}

impl Arbitrary for DebugFileInfo {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<DebugStringIdx>(), any::<[u8; 32]>())
            .prop_map(|(path_idx, checksum)| Self { path_idx, checksum })
            .boxed()
    }
}

impl Arbitrary for DebugSourceVar {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // arg_idx: the wire carries a u32 where 0 decodes to None (NonZeroU32::new), so any
        // Option<NonZeroU32> is reachable; value_location has its own arbitrary impl.
        (
            any::<u32>(),
            any::<DebugStringIdx>(),
            any::<Option<DebugTypeIdx>>(),
            any::<Option<NonZeroU32>>(),
            any::<Option<DebugLocIdx>>(),
            any::<DebugVarLocation>(),
        )
            .prop_map(|(op_idx, name_idx, type_id, arg_idx, location_idx, value_location)| Self {
                op_idx,
                name_idx,
                type_id,
                arg_idx,
                location_idx,
                value_location,
            })
            .boxed()
    }
}

impl Arbitrary for DebugSourceInlineCall {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<u32>(), any::<DebugFunctionIdx>(), any::<DebugLocIdx>())
            .prop_map(|(op_idx, callee_idx, loc_idx)| Self { op_idx, callee_idx, loc_idx })
            .boxed()
    }
}

impl Arbitrary for DebugPrimitiveType {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // A fixed variant set serialized as one byte; exercise a representative spread
        // (the full set adds no wire-coverage value beyond these tags).
        prop_oneof![
            Just(Self::Bool),
            Just(Self::I8),
            Just(Self::U32),
            Just(Self::I64),
            Just(Self::U64),
            Just(Self::I128),
        ]
        .boxed()
    }
}

impl Arbitrary for DebugTypeInfo {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // One row on the wire: nesting happens through type-table indices, not through the
        // value, so every variant is any-valid given bounded child rows.
        prop_oneof![
            any::<DebugPrimitiveType>().prop_map(Self::Primitive).boxed(),
            any::<DebugTypeIdx>()
                .prop_map(|pointee_type_idx| Self::Pointer { pointee_type_idx })
                .boxed(),
            (any::<DebugTypeIdx>(), any::<Option<u32>>())
                .prop_map(|(element_type_idx, count)| Self::Array { element_type_idx, count })
                .boxed(),
            (
                any::<DebugStringIdx>(),
                any::<u32>(),
                proptest::collection::vec(any::<DebugFieldInfo>(), 0..=4)
            )
                .prop_map(|(name_idx, size, fields)| Self::Struct { name_idx, size, fields })
                .boxed(),
            (
                any::<Option<DebugTypeIdx>>(),
                proptest::collection::vec(any::<DebugTypeIdx>(), 0..=4)
            )
                .prop_map(|(return_type_idx, param_type_indices)| Self::Function {
                    return_type_idx,
                    param_type_indices,
                })
                .boxed(),
            (
                any::<DebugStringIdx>(),
                any::<u32>(),
                any::<DebugTypeIdx>(),
                proptest::collection::vec(any::<DebugVariantInfo>(), 0..=4),
            )
                .prop_map(|(name_idx, size, discriminant_type_idx, variants)| Self::Enum {
                    name_idx,
                    size,
                    discriminant_type_idx,
                    variants,
                })
                .boxed(),
            Just(Self::Variadic),
            Just(Self::Unknown),
        ]
        .boxed()
    }
}

impl Arbitrary for DebugSourceNode {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Sound by construction: asm_ops are sorted and deduplicated by op_idx, satisfying the
        // reader's strictly-increasing validation; everything else is any-valid on the wire.
        (
            any::<MastNodeId>(),
            proptest::collection::vec(any::<DebugSourceNodeId>(), 0..=4),
            any::<u32>(),
            any::<u32>(),
            proptest::collection::vec(
                (
                    any::<u32>(),
                    any::<Option<DebugLocIdx>>(),
                    any::<DebugStringIdx>(),
                    any::<DebugStringIdx>(),
                    any::<u8>(),
                ),
                0..=4,
            ),
            proptest::collection::vec(any::<DebugSourceVar>(), 0..=4),
            proptest::collection::vec(any::<DebugSourceInlineCall>(), 0..=4),
        )
            .prop_map(
                |(exec_node, children, op_start, op_end, asm_op_rows, debug_vars, inline_calls)| {
                    let mut asm_ops: Vec<DebugSourceAsmOp> = asm_op_rows
                        .into_iter()
                        .map(|(op_idx, location_idx, context, op, cycles)| {
                            DebugSourceAsmOp::new(op_idx, location_idx, context, op, cycles)
                        })
                        .collect();
                    asm_ops.sort_by_key(|asm_op| asm_op.op_idx);
                    asm_ops.dedup_by_key(|asm_op| asm_op.op_idx);
                    Self {
                        exec_node,
                        children,
                        op_start,
                        op_end,
                        asm_ops,
                        debug_vars,
                        inline_calls,
                    }
                },
            )
            .boxed()
    }
}
