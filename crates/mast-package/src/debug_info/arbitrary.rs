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
