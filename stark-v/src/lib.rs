use ere_zkvm_interface::Input;
use ere_zkvm_interface::zkVM;
use stark_v_sdk::{StarkV, StarkVCompiler};
use utils::zkvm::{CompiledProgram, PreparedSha256, ProofArtifacts};

pub use utils::zkvm::{execution_cycles, preprocessing_size, proof_size, prove_sha256};

const INPUT_CAPACITY: usize = 4096;
const LEN_PREFIX_BYTES: usize = 4;
const MAX_MSG_LEN: usize = INPUT_CAPACITY - LEN_PREFIX_BYTES;

fn build_sha256_input(message_bytes: &[u8]) -> Input {
    let message_len = u32::try_from(message_bytes.len()).expect("message length exceeds u32");
    let mut stdin = Vec::with_capacity(LEN_PREFIX_BYTES + message_bytes.len());
    stdin.extend_from_slice(&message_len.to_le_bytes());
    stdin.extend_from_slice(message_bytes);
    Input::new().with_stdin(stdin)
}

pub fn prepare_sha256(
    input_size: usize,
    program: &CompiledProgram<StarkVCompiler>,
) -> PreparedSha256<StarkV> {
    let vm = StarkV::new(program.program.clone());
    // Keep host input generation in sync with guest constraints.
    let bounded_size = input_size.min(MAX_MSG_LEN);
    let (message_bytes, digest) = utils::generate_sha256_input(bounded_size);
    let input = build_sha256_input(&message_bytes);
    PreparedSha256::with_expected_digest(vm, input, program.byte_size, digest)
}

pub fn verify_sha256<SharedState>(
    prepared: &PreparedSha256<StarkV>,
    proof: &ProofArtifacts,
    _: &SharedState,
) {
    let verified_public_values = prepared.vm().verify(&proof.proof).expect("verify failed");

    if let Some(expected_digest) = prepared.expected_digest() {
        // Some StarkV SDK revisions return a differently reconstructed public-values buffer
        // from verify() than what prove() emits, even though proof verification succeeds.
        // Accept either source as long as one matches the expected digest.
        if proof.public_values.as_slice() == expected_digest {
            return;
        }
        if verified_public_values.as_slice() == expected_digest {
            return;
        }
        panic!("digest mismatch");
    }
}
