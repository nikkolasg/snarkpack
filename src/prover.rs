use ark_ec::{group::Group, AffineCurve, PairingEngine};
use ark_ff::{to_bytes, Field, One};
use ark_groth16::{Proof, VerifyingKey};

pub fn aggregate<E: PairingEngine>(proofs: &[Proof<E>]) {}
