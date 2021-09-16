#[macro_use]
mod macros;

mod commitment;
mod errors;
mod ip;
mod pairing_check;
mod proof;
mod prover;
pub mod srs;
pub mod transcript;
mod verifier;

pub use errors::*;
pub use prover::*;
pub use verifier::*;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use rayon::prelude::*;
use std::ops::MulAssign;
/// Returns the vector used for the linear combination fo the inner pairing product
/// between A and B for the Groth16 aggregation: A^r * B. It is required as it
/// is not enough to simply prove the ipp of A*B, we need a random linear
/// combination of those.
pub(crate) fn structured_scalar_power<F: Field>(num: usize, s: &F) -> Vec<F> {
    let mut powers = vec![F::one()];
    for i in 1..num {
        powers.push(powers[i - 1] * s);
    }
    powers
}

/// compress is similar to commit::{V,W}KEY::compress: it modifies the `vec`
/// vector by setting the value at index $i:0 -> split$  $vec[i] = vec[i] +
/// vec[i+split]^scaler$. The `vec` vector is half of its size after this call.
pub(crate) fn compress<C: AffineCurve>(vec: &mut Vec<C>, split: usize, scaler: &C::ScalarField) {
    let (left, right) = vec.split_at_mut(split);
    left.par_iter_mut()
        .zip(right.par_iter())
        .for_each(|(a_l, a_r)| {
            //let mut x = mul!(a_r.into_projective(), scaler.clone());
            let sc = scaler.clone();
            let mut x = a_r.mul(sc);
            x.add_assign_mixed(&a_l);
            *a_l = x.into_affine();
        });
    let len = left.len();
    vec.resize(len, C::zero());
}
