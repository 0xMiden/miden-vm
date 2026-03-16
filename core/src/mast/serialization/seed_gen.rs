//! Test helper for generating fuzz corpus seeds.
//!
//! Run with: cargo test -p miden-core generate_fuzz_seeds -- --ignored --nocapture

use alloc::{sync::Arc, vec::Vec};
use std::println;

use crate::{
    Felt, Word,
    advice::{AdviceInputs, AdviceMap},
    events::EventId,
    mast::{BasicBlockNodeBuilder, JoinNodeBuilder, MastForest, MastForestContributor},
    operations::Operation,
    precompile::PrecompileRequest,
    program::{Kernel, Program, StackInputs, StackOutputs},
    proof::{ExecutionProof, HashFunction},
    serde::{ByteWriter, Serializable},
};

/// Generates seed corpus files for fuzzing.
/// Run with: cargo test -p miden-core generate_fuzz_seeds -- --ignored --nocapture
#[test]
#[ignore = "run manually to generate fuzz seeds"]
fn generate_fuzz_seeds() {
    fn write_seed(target: &str, name: &str, bytes: &[u8]) {
        let corpus_dir = std::path::Path::new("../miden-core-fuzz/corpus").join(target);
        std::fs::create_dir_all(&corpus_dir).expect("Failed to create corpus directory");
        std::fs::write(corpus_dir.join(name), bytes).unwrap();
        println!("Generated {}/{} ({} bytes)", target, name, bytes.len());
    }

    // Seed 1: Minimal valid forest (single basic block)
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let bytes = forest.to_bytes();
        write_seed("mast_forest_deserialize", "minimal_block.bin", &bytes);
    }

    // Seed 2: Forest with join node
    {
        let mut forest = MastForest::new();
        let block1 = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        let block2 = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut forest).unwrap();
        forest.make_root(join);

        let bytes = forest.to_bytes();
        write_seed("mast_forest_deserialize", "join_node.bin", &bytes);
    }

    // Seed 3: Stripped forest (no debug info)
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let mut bytes = Vec::new();
        forest.write_stripped(&mut bytes);
        write_seed("mast_forest_deserialize", "stripped.bin", &bytes);
    }

    // Seed 4: Empty header (just magic + flags + version + minimal counts)
    {
        let bytes: &[u8] = b"MAST\x00\x00\x00\x01";
        write_seed("mast_forest_deserialize", "header_only.bin", bytes);
    }

    // Seed 5: Invalid magic
    {
        let bytes: &[u8] = b"XXXX\x00\x00\x00\x01";
        write_seed("mast_forest_deserialize", "invalid_magic.bin", bytes);
    }

    // Program seed
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);
        let program = Program::new(Arc::new(forest), block_id);
        write_seed("program_deserialize", "minimal_program.bin", &program.to_bytes());
    }

    // Program seed with invalid duplicate-kernel payload.
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let a: Word = [Felt::new(9), Felt::new(10), Felt::new(11), Felt::new(12)].into();

        let mut invalid_program = Vec::new();
        forest.write_into(&mut invalid_program);
        invalid_program.write_u8(2);
        a.write_into(&mut invalid_program);
        a.write_into(&mut invalid_program);
        invalid_program.write_u32(block_id.into());

        write_seed("program_deserialize", "program_with_duplicate_kernel.bin", &invalid_program);
    }

    // Kernel seed
    {
        let kernel = Kernel::default();
        write_seed("kernel_deserialize", "empty_kernel.bin", &kernel.to_bytes());

        let a: Word = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
        let b: Word = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into();

        let non_empty = Kernel::new(&[a]).expect("failed to build non-empty kernel");
        write_seed("kernel_deserialize", "single_kernel.bin", &non_empty.to_bytes());

        let max_kernel: Vec<Word> = (0u64..=254)
            .map(|n| [Felt::new(n), Felt::new(n + 1), Felt::new(n + 2), Felt::new(n + 3)].into())
            .collect();
        let max_kernel = Kernel::new(&max_kernel).expect("failed to build max-size kernel");
        write_seed("kernel_deserialize", "max_kernel_255.bin", &max_kernel.to_bytes());

        // Invalid seed: duplicate hashes should deserialize to Err (never panic).
        let mut duplicate_kernel = Vec::new();
        duplicate_kernel.write_u8(3);
        b.write_into(&mut duplicate_kernel);
        a.write_into(&mut duplicate_kernel);
        a.write_into(&mut duplicate_kernel);
        write_seed("kernel_deserialize", "duplicate_kernel.bin", &duplicate_kernel);

        // Serde kernel seeds (JSON payloads) used by kernel_serde_deserialize fuzz target.
        write_seed("kernel_serde_deserialize", "empty_kernel.json", b"[]");
        write_seed("kernel_serde_deserialize", "duplicate_kernel.json", b"[[1,2,3,4],[1,2,3,4]]");
        write_seed("kernel_serde_deserialize", "too_many_hashes.json", br#"[
            [0,1,2,3],[1,2,3,4],[2,3,4,5],[3,4,5,6],[4,5,6,7],[5,6,7,8],[6,7,8,9],[7,8,9,10],
            [8,9,10,11],[9,10,11,12],[10,11,12,13],[11,12,13,14],[12,13,14,15],[13,14,15,16],
            [14,15,16,17],[15,16,17,18],[16,17,18,19],[17,18,19,20],[18,19,20,21],[19,20,21,22],
            [20,21,22,23],[21,22,23,24],[22,23,24,25],[23,24,25,26],[24,25,26,27],[25,26,27,28],
            [26,27,28,29],[27,28,29,30],[28,29,30,31],[29,30,31,32],[30,31,32,33],[31,32,33,34],
            [32,33,34,35],[33,34,35,36],[34,35,36,37],[35,36,37,38],[36,37,38,39],[37,38,39,40],
            [38,39,40,41],[39,40,41,42],[40,41,42,43],[41,42,43,44],[42,43,44,45],[43,44,45,46],
            [44,45,46,47],[45,46,47,48],[46,47,48,49],[47,48,49,50],[48,49,50,51],[49,50,51,52],
            [50,51,52,53],[51,52,53,54],[52,53,54,55],[53,54,55,56],[54,55,56,57],[55,56,57,58],
            [56,57,58,59],[57,58,59,60],[58,59,60,61],[59,60,61,62],[60,61,62,63],[61,62,63,64],
            [62,63,64,65],[63,64,65,66],[64,65,66,67],[65,66,67,68],[66,67,68,69],[67,68,69,70],
            [68,69,70,71],[69,70,71,72],[70,71,72,73],[71,72,73,74],[72,73,74,75],[73,74,75,76],
            [74,75,76,77],[75,76,77,78],[76,77,78,79],[77,78,79,80],[78,79,80,81],[79,80,81,82],
            [80,81,82,83],[81,82,83,84],[82,83,84,85],[83,84,85,86],[84,85,86,87],[85,86,87,88],
            [86,87,88,89],[87,88,89,90],[88,89,90,91],[89,90,91,92],[90,91,92,93],[91,92,93,94],
            [92,93,94,95],[93,94,95,96],[94,95,96,97],[95,96,97,98],[96,97,98,99],[97,98,99,100],
            [98,99,100,101],[99,100,101,102],[100,101,102,103],[101,102,103,104],[102,103,104,105],
            [103,104,105,106],[104,105,106,107],[105,106,107,108],[106,107,108,109],[107,108,109,110],
            [108,109,110,111],[109,110,111,112],[110,111,112,113],[111,112,113,114],[112,113,114,115],
            [113,114,115,116],[114,115,116,117],[115,116,117,118],[116,117,118,119],[117,118,119,120],
            [118,119,120,121],[119,120,121,122],[120,121,122,123],[121,122,123,124],[122,123,124,125],
            [123,124,125,126],[124,125,126,127],[125,126,127,128],[126,127,128,129],[127,128,129,130],
            [128,129,130,131],[129,130,131,132],[130,131,132,133],[131,132,133,134],[132,133,134,135],
            [133,134,135,136],[134,135,136,137],[135,136,137,138],[136,137,138,139],[137,138,139,140],
            [138,139,140,141],[139,140,141,142],[140,141,142,143],[141,142,143,144],[142,143,144,145],
            [143,144,145,146],[144,145,146,147],[145,146,147,148],[146,147,148,149],[147,148,149,150],
            [148,149,150,151],[149,150,151,152],[150,151,152,153],[151,152,153,154],[152,153,154,155],
            [153,154,155,156],[154,155,156,157],[155,156,157,158],[156,157,158,159],[157,158,159,160],
            [158,159,160,161],[159,160,161,162],[160,161,162,163],[161,162,163,164],[162,163,164,165],
            [163,164,165,166],[164,165,166,167],[165,166,167,168],[166,167,168,169],[167,168,169,170],
            [168,169,170,171],[169,170,171,172],[170,171,172,173],[171,172,173,174],[172,173,174,175],
            [173,174,175,176],[174,175,176,177],[175,176,177,178],[176,177,178,179],[177,178,179,180],
            [178,179,180,181],[179,180,181,182],[180,181,182,183],[181,182,183,184],[182,183,184,185],
            [183,184,185,186],[184,185,186,187],[185,186,187,188],[186,187,188,189],[187,188,189,190],
            [188,189,190,191],[189,190,191,192],[190,191,192,193],[191,192,193,194],[192,193,194,195],
            [193,194,195,196],[194,195,196,197],[195,196,197,198],[196,197,198,199],[197,198,199,200],
            [198,199,200,201],[199,200,201,202],[200,201,202,203],[201,202,203,204],[202,203,204,205],
            [203,204,205,206],[204,205,206,207],[205,206,207,208],[206,207,208,209],[207,208,209,210],
            [208,209,210,211],[209,210,211,212],[210,211,212,213],[211,212,213,214],[212,213,214,215],
            [213,214,215,216],[214,215,216,217],[215,216,217,218],[216,217,218,219],[217,218,219,220],
            [218,219,220,221],[219,220,221,222],[220,221,222,223],[221,222,223,224],[222,223,224,225],
            [223,224,225,226],[224,225,226,227],[225,226,227,228],[226,227,228,229],[227,228,229,230],
            [228,229,230,231],[229,230,231,232],[230,231,232,233],[231,232,233,234],[232,233,234,235],
            [233,234,235,236],[234,235,236,237],[235,236,237,238],[236,237,238,239],[237,238,239,240],
            [238,239,240,241],[239,240,241,242],[240,241,242,243],[241,242,243,244],[242,243,244,245],
            [243,244,245,246],[244,245,246,247],[245,246,247,248],[246,247,248,249],[247,248,249,250],
            [248,249,250,251],[249,250,251,252],[250,251,252,253],[251,252,253,254],[252,253,254,255],
            [253,254,255,256],[254,255,256,257],[255,256,257,258]
        ]"#);
    }

    // Stack IO seeds
    {
        let inputs = StackInputs::new(&[Felt::new(1), Felt::new(2)]).unwrap();
        let outputs = StackOutputs::new(&[Felt::new(3), Felt::new(4)]).unwrap();
        write_seed("stack_io_deserialize", "stack_inputs.bin", &inputs.to_bytes());
        write_seed("stack_io_deserialize", "stack_outputs.bin", &outputs.to_bytes());
    }

    // Advice inputs seed
    {
        let advice = AdviceInputs::default();
        let advice_map = AdviceMap::default();
        write_seed("advice_inputs_deserialize", "advice_inputs.bin", &advice.to_bytes());
        write_seed("advice_inputs_deserialize", "advice_map.bin", &advice_map.to_bytes());
    }

    // Operation seed
    {
        let op = Operation::Add;
        write_seed("operation_deserialize", "op_add.bin", &op.to_bytes());
    }

    // Precompile request seed
    {
        let request = PrecompileRequest::new(EventId::from_u64(1), vec![1, 2, 3, 4]);
        write_seed("precompile_request_deserialize", "precompile_request.bin", &request.to_bytes());
    }

    // Execution proof seed (minimal)
    {
        let request = PrecompileRequest::new(EventId::from_u64(1), vec![1, 2, 3, 4]);
        let proof = ExecutionProof::new(Vec::new(), HashFunction::Rpo256, vec![request]);
        write_seed("execution_proof_deserialize", "minimal_proof.bin", &proof.to_bytes());
    }

    println!("\nSeed corpus generated in ../miden-core-fuzz/corpus");
}
