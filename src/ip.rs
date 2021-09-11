use crate::Error;
use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine};
use ark_ff::PrimeField;
use ark_std::{cfg_iter, vec::Vec};
use rayon::prelude::*;

pub(crate) fn pairing_miller_affine<E: PairingEngine>(
    left: &[E::G1Affine],
    right: &[E::G2Affine],
) -> Result<E::Fqk, Error> {
    if left.len() != right.len() {
        return Err(Error::InvalidIPVectorLength);
    }
    let pairs: Vec<(E::G1Prepared, E::G2Prepared)> = left
        .par_iter()
        .map(|e| E::G1Prepared::from(*e))
        .zip(right.par_iter().map(|e| E::G2Prepared::from(*e)))
        .collect::<Vec<_>>();

    Ok(E::miller_loop(pairs.iter()))
}

/// Returns the miller loop result of the inner pairing product
pub(crate) fn pairing<E: PairingEngine>(
    left: &[E::G1Affine],
    right: &[E::G2Affine],
) -> Result<E::Fqk, Error> {
    E::final_exponentiation(&pairing_miller_affine::<E>(left, right)?).ok_or(Error::InvalidPairing)
}

pub(crate) fn multiexponentiation<G: AffineCurve>(
    left: &[G],
    right: &[G::ScalarField],
) -> Result<G::Projective, Error> {
    if left.len() != right.len() {
        return Err(Error::InvalidIPVectorLength);
    }

    Ok(VariableBaseMSM::multi_scalar_mul(
        left,
        &cfg_iter!(right).map(|s| s.into_repr()).collect::<Vec<_>>(),
    ))
}
