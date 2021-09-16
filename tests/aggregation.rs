use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::One;
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use ark_std::test_rng;
use snarkpack;
use snarkpack::transcript::Transcript;
use std::{
    error::Error,
    time::{Duration, Instant},
};

mod constraints;
use crate::constraints::Benchmark;
use ark_std::{rand::Rng, UniformRand};
use rand_core::{RngCore, SeedableRng};

#[test]
fn groth16_aggregation() {
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1u64);
    let num_constraints = 1000;
    let params = {
        let c = Benchmark::<Fr>::new(num_constraints);
        generate_random_parameters::<Bls12_381, _, _>(c, &mut rng).unwrap()
    };
    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);
    let nproofs = 8;
    let srs = snarkpack::srs::setup_fake_srs::<Bls12_381, _>(&mut rng, nproofs * 2 + 1);
    let (prover_srs, ver_srs) = srs.specialize(nproofs);
    let proofs = (0..nproofs)
        .map(|_| {
            // Create an instance of our circuit (with the witness)
            let c = Benchmark::new(num_constraints);
            // Create a proof with our parameters.
            create_random_proof(c, &params, &mut rng).expect("proof creation failed")
        })
        .collect::<Vec<_>>();
    // verify we can at least verify one
    let inputs: Vec<_> = [Fr::one(); 2].to_vec();
    let all_inputs = (0..nproofs).map(|_| inputs.clone()).collect::<Vec<_>>();
    let r = verify_proof(&pvk, &proofs[0], &inputs).unwrap();
    assert!(r);

    let mut prover_transcript = snarkpack::transcript::new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let aggregate_proof = snarkpack::aggregate_proofs(&prover_srs, &mut prover_transcript, &proofs)
        .expect("error in aggregation");

    let mut ver_transcript = snarkpack::transcript::new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &all_inputs);
    snarkpack::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_inputs,
        &aggregate_proof,
        &mut rng,
        &mut ver_transcript,
    )
    .expect("error in verification");
}
