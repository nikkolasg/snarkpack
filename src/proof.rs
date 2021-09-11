use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use std::io::{Read, Write};

use super::Error;
use super::{
    commitment::{self, Output},
    srs,
};

/// AggregateProof contains all elements to verify n aggregated Groth16 proofs
/// using inner pairing product arguments. This proof can be created by any
/// party in possession of valid Groth16 proofs.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct AggregateProof<E: PairingEngine> {
    /// commitment to A and B using the pair commitment scheme needed to verify
    /// TIPP relation.
    pub com_ab: commitment::Output<E::Fqk>,
    /// commit to C separate since we use it only in MIPP
    pub com_c: commitment::Output<E::Fqk>,
    /// $A^r * B = Z$ is the left value on the aggregated Groth16 equation
    pub ip_ab: E::Fqk,
    /// $C^r$ is used on the right side of the aggregated Groth16 equation
    pub agg_c: E::G1Affine,
    pub tmipp: TippMippProof<E>,
}

impl<E: PairingEngine> PartialEq for AggregateProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.com_ab == other.com_ab
            && self.com_c == other.com_c
            && self.ip_ab == other.ip_ab
            && self.agg_c == other.agg_c
            && self.tmipp == other.tmipp
    }
}

impl<E: PairingEngine> AggregateProof<E> {
    /// Performs some high level checks on the length of vectors and others to
    /// make sure all items in the proofs are consistent with each other.
    pub fn parsing_check(&self) -> Result<(), Error> {
        let gipa = &self.tmipp.gipa;
        // 1. Check length of the proofs
        if gipa.nproofs < 2 || gipa.nproofs as usize > srs::MAX_SRS_SIZE {
            return Err(Error::InvalidProof(
                "Proof length out of bounds".to_string(),
            ));
        }
        // 2. Check if it's a power of two
        if !gipa.nproofs.is_power_of_two() {
            return Err(Error::InvalidProof(
                "Proof length not a power of two".to_string(),
            ));
        }
        // 3. Check all vectors are of the same length and of the correct length
        let ref_len = (gipa.nproofs as f32).log2().ceil() as usize;
        let all_same = ref_len == gipa.comms_ab.len()
            && ref_len == gipa.comms_c.len()
            && ref_len == gipa.z_ab.len()
            && ref_len == gipa.z_c.len();
        if !all_same {
            return Err(Error::InvalidProof(
                "Proof vectors unequal sizes".to_string(),
            ));
        }
        Ok(())
    }

    /// Writes the aggregate proof to the given destination. This method is for
    /// high level protocol to use it as a library. If you want to use within
    /// another arkwork protocol, you can use the underlying implementation of
    /// `CanonicalSerialize`.
    pub fn write<W: Write>(&self, mut out: W) -> Result<(), Error> {
        self.serialize(&mut out)
            .map_err(|e| Error::Serialization(e))
    }

    /// Reads the aggregate proof to the given destination. This method is for
    /// high level protocol to use it as a library. If you want to use within
    /// another arkwork protocol, you can use the underlying implementation of
    /// `CanonicalSerialize`.
    pub fn read<R: Read>(mut source: R) -> Result<Self, Error> {
        Self::deserialize(&mut source).map_err(|e| Error::Serialization(e))
    }
}

/// It contains all elements derived in the GIPA loop for both TIPP and MIPP at
/// the same time. Serialization is done manually here for better inspection
/// (CanonicalSerialization is implemented manually, not via the macro).
pub struct GipaProof<E: PairingEngine> {
    pub nproofs: u32,
    pub comms_ab: Vec<(commitment::Output<E::Fqk>, commitment::Output<E::Fqk>)>,
    pub comms_c: Vec<(commitment::Output<E::Fqk>, commitment::Output<E::Fqk>)>,
    pub z_ab: Vec<(E::Fqk, E::Fqk)>,
    pub z_c: Vec<(E::G1Affine, E::G1Affine)>,
    pub final_a: E::G1Affine,
    pub final_b: E::G2Affine,
    pub final_c: E::G1Affine,
    /// final commitment keys $v$ and $w$ - there is only one element at the
    /// end for v1 and v2 hence it's a tuple.
    pub final_vkey: (E::G2Affine, E::G2Affine),
    pub final_wkey: (E::G1Affine, E::G1Affine),
}

impl<E: PairingEngine> PartialEq for GipaProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.nproofs == other.nproofs
            && self.comms_ab == other.comms_ab
            && self.comms_c == other.comms_c
            && self.z_ab == other.z_ab
            && self.z_c == other.z_c
            && self.final_a == other.final_a
            && self.final_b == other.final_b
            && self.final_c == other.final_c
            && self.final_vkey == other.final_vkey
            && self.final_wkey == other.final_wkey
    }
}

impl<E: PairingEngine> GipaProof<E> {
    fn log_proofs(nproofs: usize) -> usize {
        (nproofs as f32).log2().ceil() as usize
    }
}

impl<E: PairingEngine> CanonicalSerialize for GipaProof<E> {
    fn serialized_size(&self) -> usize {
        let log_proofs = Self::log_proofs(self.nproofs as usize);
        (self.nproofs as u32).serialized_size()
            + log_proofs
                * (self.comms_ab[0].0.serialized_size()
                    + self.comms_ab[0].1.serialized_size()
                    + self.comms_c[0].0.serialized_size()
                    + self.comms_c[0].1.serialized_size()
                    + self.z_ab[0].0.serialized_size()
                    + self.z_ab[0].1.serialized_size()
                    + self.z_c[0].0.serialized_size()
                    + self.z_c[0].1.serialized_size()
                    + self.final_a.serialized_size()
                    + self.final_b.serialized_size()
                    + self.final_c.serialized_size()
                    + self.final_vkey.serialized_size()
                    + self.final_wkey.serialized_size())
    }
    fn serialize<W: Write>(&self, mut out: W) -> Result<(), SerializationError> {
        // number of proofs
        self.nproofs.serialize(&mut out)?;

        let log_proofs = Self::log_proofs(self.nproofs as usize);
        assert_eq!(self.comms_ab.len(), log_proofs);

        // comms_ab
        for (x, y) in &self.comms_ab {
            x.serialize(&mut out)?;
            y.serialize(&mut out)?;
        }

        assert_eq!(self.comms_c.len(), log_proofs);
        // comms_c
        for (x, y) in &self.comms_c {
            x.serialize(&mut out)?;
            y.serialize(&mut out)?;
        }

        assert_eq!(self.z_ab.len(), log_proofs);
        // z_ab
        for (x, y) in &self.z_ab {
            x.serialize(&mut out)?;
            y.serialize(&mut out)?;
        }

        assert_eq!(self.z_c.len(), log_proofs);
        // z_c
        for (x, y) in &self.z_c {
            x.serialize(&mut out)?;
            y.serialize(&mut out)?;
        }

        // final values of the loop
        self.final_a.serialize(&mut out)?;
        self.final_b.serialize(&mut out)?;
        self.final_c.serialize(&mut out)?;

        // final commitment keys
        self.final_vkey.serialize(&mut out)?;
        self.final_wkey.serialize(&mut out)?;

        Ok(())
    }
}

impl<E> CanonicalDeserialize for GipaProof<E>
where
    E: PairingEngine,
{
    fn deserialize<R: Read>(mut source: R) -> Result<Self, SerializationError> {
        let nproofs = u32::deserialize(&mut source)?;
        if nproofs < 2 {
            return Err(SerializationError::InvalidData);
        }

        let log_proofs = Self::log_proofs(nproofs as usize);

        let mut comms_ab = Vec::with_capacity(log_proofs);
        for _ in 0..log_proofs {
            comms_ab.push((
                Output::<E::Fqk>::deserialize(&mut source)?,
                Output::<E::Fqk>::deserialize(&mut source)?,
            ));
        }

        let mut comms_c = Vec::with_capacity(log_proofs);
        for _ in 0..log_proofs {
            comms_c.push((
                Output::<E::Fqk>::deserialize(&mut source)?,
                Output::<E::Fqk>::deserialize(&mut source)?,
            ));
        }

        let mut z_ab = Vec::with_capacity(log_proofs);
        for _ in 0..log_proofs {
            z_ab.push((
                E::Fqk::deserialize(&mut source)?,
                E::Fqk::deserialize(&mut source)?,
            ));
        }

        let mut z_c = Vec::with_capacity(log_proofs);
        for _ in 0..log_proofs {
            z_c.push((
                E::G1Affine::deserialize(&mut source)?,
                E::G1Affine::deserialize(&mut source)?,
            ));
        }

        let final_a = E::G1Affine::deserialize(&mut source)?;
        let final_b = E::G2Affine::deserialize(&mut source)?;
        let final_c = E::G1Affine::deserialize(&mut source)?;

        let final_vkey = (
            E::G2Affine::deserialize(&mut source)?,
            E::G2Affine::deserialize(&mut source)?,
        );
        let final_wkey = (
            E::G1Affine::deserialize(&mut source)?,
            E::G1Affine::deserialize(&mut source)?,
        );

        Ok(GipaProof {
            nproofs,
            comms_ab,
            comms_c,
            z_ab,
            z_c,
            final_a,
            final_b,
            final_c,
            final_vkey,
            final_wkey,
        })
    }
}

/// It contains the GIPA recursive elements as well as the KZG openings for v
/// and w
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct TippMippProof<E: PairingEngine> {
    pub gipa: GipaProof<E>,
    pub vkey_opening: KZGOpening<E::G2Affine>,
    pub wkey_opening: KZGOpening<E::G1Affine>,
}

impl<E: PairingEngine> PartialEq for TippMippProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.gipa == other.gipa
            && self.vkey_opening == other.vkey_opening
            && self.wkey_opening == other.wkey_opening
    }
}

/// KZGOpening represents the KZG opening of a commitment key (which is a tuple
/// given commitment keys are a tuple).
#[derive(PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGOpening<G: AffineCurve>(G, G);

impl<G: AffineCurve> KZGOpening<G> {
    pub fn new_from_proj(a: G::Projective, b: G::Projective) -> Self {
        KZGOpening(a.into_affine(), b.into_affine())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bls::{Bls12, G1Affine, G1Projective, G2Affine, G2Projective};

    fn fake_proof() -> AggregateProof<Bls12> {
        // create pairing, as pairing results can be compressed
        let p = G1Projective::one().into_affine();
        let q = G2Projective::one().into_affine();
        let a = Bls12::pairing(p, q);

        let proof = AggregateProof::<Bls12> {
            com_ab: (a, a),
            com_c: (a, a),
            ip_ab: a,
            agg_c: G1Projective::one(),
            tmipp: TippMippProof::<Bls12> {
                gipa: GipaProof {
                    nproofs: 4,
                    comms_ab: vec![((a, a), (a, a)), ((a, a), (a, a))],
                    comms_c: vec![((a, a), (a, a)), ((a, a), (a, a))],
                    z_ab: vec![(a, a), (a, a)],
                    z_c: vec![
                        (G1Projective::one(), G1Projective::one()),
                        (G1Projective::one(), G1Projective::one()),
                    ],
                    final_a: G1Affine::one(),
                    final_b: G2Affine::one(),
                    final_c: G1Affine::one(),
                    final_vkey: (G2Affine::one(), G2Affine::one()),
                    final_wkey: (G1Affine::one(), G1Affine::one()),
                },
                vkey_opening: (G2Affine::one(), G2Affine::one()),
                wkey_opening: (G1Affine::one(), G1Affine::one()),
            },
        };
        proof
    }

    #[test]
    fn test_proof_io() {
        let proof = fake_proof();
        let mut buffer = Vec::new();
        proof.write(&mut buffer).unwrap();
        assert_eq!(buffer.len(), 8_212);

        let out = AggregateProof::<Bls12>::read(std::io::Cursor::new(&buffer)).unwrap();
        assert_eq!(proof, out);
    }

    #[test]
    fn test_proof_check() {
        let p = G1Projective::one().into_affine();
        let q = G2Projective::one().into_affine();
        let a = Bls12::pairing(p, q);

        let mut proof = fake_proof();
        proof.parsing_check().expect("proof should be valid");

        let oldn = proof.tmipp.gipa.nproofs;
        proof.tmipp.gipa.nproofs = 14;
        proof.parsing_check().expect_err("proof should be invalid");
        proof.tmipp.gipa.nproofs = oldn;

        proof
            .tmipp
            .gipa
            .comms_ab
            .append(&mut vec![((a, a), (a, a))]);
        proof.parsing_check().expect_err("Proof should be invalid");
    }
}
