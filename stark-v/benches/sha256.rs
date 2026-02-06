use stark_v::{
    execution_cycles, prepare_sha256, preprocessing_size, proof_size, prove_sha256, verify_sha256,
};
use stark_v_sdk::StarkVCompiler;
use utils::harness::ProvingSystem;
use utils::zkvm::SHA256_BENCH;
use utils::zkvm::helpers::load_or_compile_program;

utils::define_benchmark_harness!(
    BenchTarget::Sha256,
    ProvingSystem::StarkV,
    None,
    "sha256_mem_stark_v",
    utils::harness::BenchProperties {
        is_zkvm: true,
        ..Default::default()
    },
    { load_or_compile_program(&StarkVCompiler::new(), SHA256_BENCH) },
    prepare_sha256,
    |_, _| 0,
    prove_sha256,
    verify_sha256,
    preprocessing_size,
    proof_size,
    execution_cycles
);
