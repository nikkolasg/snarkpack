use ark_ec::msm::FixedBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{rand::Rng, One, UniformRand};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

use std::clone::Clone;

use super::commitment::{VKey, WKey};
use crate::Error;

use std::ops::MulAssign;
/// Maximum size of the generic SRS constructed from Filecoin and Zcash power of
/// taus.
///
/// https://github.com/nikkolasg/taupipp/blob/baca1426266bf39416c45303e35c966d69f4f8b4/src/bin/assemble.rs#L12
pub const MAX_SRS_SIZE: usize = (2 << 19) + 1;

/// It contains the maximum number of raw elements of the SRS needed to
/// aggregate and verify Groth16 proofs. One can derive specialized prover and
/// verifier key for _specific_ size of aggregations by calling
/// `srs.specialize(n)`. The specialized prover key also contains precomputed
/// tables that drastically increase prover's performance.  This GenericSRS is
/// usually formed from the transcript of two distinct power of taus ceremony
/// ,in other words from two distinct Groth16 CRS.
/// See [there](https://github.com/nikkolasg/taupipp) a way on how to generate
/// this GenesisSRS.
#[derive(Clone, Debug)]
pub struct GenericSRS<E: PairingEngine> {
    /// $\{g^a^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub g_alpha_powers: Vec<E::G1Affine>,
    /// $\{h^a^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub h_alpha_powers: Vec<E::G2Affine>,
    /// $\{g^b^i\}_{i=n}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub g_beta_powers: Vec<E::G1Affine>,
    /// $\{h^b^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub h_beta_powers: Vec<E::G2Affine>,
}

/// ProverSRS is the specialized SRS version for the prover for a specific number of proofs to
/// aggregate. It contains as well the commitment keys for this specific size.
/// Note the size must be a power of two for the moment - if it is not, padding must be
/// applied.
#[derive(Clone, Debug)]
pub struct ProverSRS<E: PairingEngine> {
    /// number of proofs to aggregate
    pub n: usize,
    /// $\{g^a^i\}_{i=0}^{2n-1}$ where n is the number of proofs to be aggregated
    /// We take all powers instead of only ones from n -> 2n-1 (w commitment key
    /// is formed from these powers) since the prover will create a shifted
    /// polynomial of degree 2n-1 when doing the KZG opening proof.
    pub g_alpha_powers_table: Vec<E::G1Affine>,
    /// $\{h^a^i\}_{i=0}^{n-1}$ - here we don't need to go to 2n-1 since v
    /// commitment key only goes up to n-1 exponent.
    pub h_alpha_powers_table: Vec<E::G2Affine>,
    /// $\{g^b^i\}_{i=0}^{2n-1}$
    pub g_beta_powers_table: Vec<E::G1Affine>,
    /// $\{h^b^i\}_{i=0}^{n-1}$
    pub h_beta_powers_table: Vec<E::G2Affine>,
    /// commitment key using in MIPP and TIPP
    pub vkey: VKey<E>,
    /// commitment key using in TIPP
    pub wkey: WKey<E>,
}

/// Contains the necessary elements to verify an aggregated Groth16 proof; it is of fixed size
/// regardless of the number of proofs aggregated. However, a verifier SRS will be determined by
/// the number of proofs being aggregated.
#[derive(Clone, Debug)]
pub struct VerifierSRS<E: PairingEngine> {
    pub n: usize,
    pub g: E::G1Projective,
    pub h: E::G2Projective,
    pub g_alpha: E::G1Projective,
    pub g_beta: E::G1Projective,
    pub h_alpha: E::G2Projective,
    pub h_beta: E::G2Projective,
}

impl<E: PairingEngine> PartialEq for GenericSRS<E> {
    fn eq(&self, other: &Self) -> bool {
        self.g_alpha_powers == other.g_alpha_powers
            && self.g_beta_powers == other.g_beta_powers
            && self.h_alpha_powers == other.h_alpha_powers
            && self.h_beta_powers == other.h_beta_powers
    }
}

impl<E: PairingEngine> PartialEq for VerifierSRS<E> {
    fn eq(&self, other: &Self) -> bool {
        self.g == other.g
            && self.h == other.h
            && self.g_alpha == other.g_alpha
            && self.g_beta == other.g_beta
            && self.h_alpha == other.h_alpha
            && self.h_beta == other.h_beta
    }
}

impl<E: PairingEngine> ProverSRS<E> {
    /// Returns true if commitment keys have the exact required length.
    /// It is necessary for the IPP scheme to work that commitment
    /// key have the exact same number of arguments as the number of proofs to
    /// aggregate.
    pub fn has_correct_len(&self, n: usize) -> bool {
        self.vkey.has_correct_len(n) && self.wkey.has_correct_len(n)
    }
}

impl<E: PairingEngine> GenericSRS<E> {
    /// specializes returns the prover and verifier SRS for a specific number of
    /// proofs to aggregate. The number of proofs MUST BE a power of two, it
    /// panics otherwise. The number of proofs must be inferior to half of the
    /// size of the generic srs otherwise it panics.
    pub fn specialize(&self, num_proofs: usize) -> (ProverSRS<E>, VerifierSRS<E>) {
        assert!(num_proofs.is_power_of_two());
        let tn = 2 * num_proofs; // size of the CRS we need
        assert!(self.g_alpha_powers.len() >= tn);
        assert!(self.h_alpha_powers.len() >= tn);
        assert!(self.g_beta_powers.len() >= tn);
        assert!(self.h_beta_powers.len() >= tn);
        let n = num_proofs;
        // when doing the KZG opening we need _all_ coefficients from 0
        // to 2n-1 because the polynomial is of degree 2n-1.
        let g_low = 0;
        let g_up = tn;
        let h_low = 0;
        let h_up = h_low + n;
        // TODO  precompute window
        let g_alpha_powers_table = self.g_alpha_powers[g_low..g_up].to_vec();
        let g_beta_powers_table = self.g_beta_powers[g_low..g_up].to_vec();
        let h_alpha_powers_table = self.h_alpha_powers[h_low..h_up].to_vec();
        let h_beta_powers_table = self.h_beta_powers[h_low..h_up].to_vec();

        println!(
            "\nPROVER SRS -- nun_proofs {}, tn {}, alpha_power_table {}\n",
            num_proofs,
            tn,
            g_alpha_powers_table.len()
        );

        let v1 = self.h_alpha_powers[h_low..h_up].to_vec();
        let v2 = self.h_beta_powers[h_low..h_up].to_vec();
        let vkey = VKey::<E> { a: v1, b: v2 };
        assert!(vkey.has_correct_len(n));
        // however, here we only need the "right" shifted bases for the
        // commitment scheme.
        let w1 = self.g_alpha_powers[n..g_up].to_vec();
        let w2 = self.g_beta_powers[n..g_up].to_vec();
        let wkey = WKey::<E> { a: w1, b: w2 };
        assert!(wkey.has_correct_len(n));
        let pk = ProverSRS::<E> {
            g_alpha_powers_table,
            g_beta_powers_table,
            h_alpha_powers_table,
            h_beta_powers_table,
            vkey,
            wkey,
            n,
        };
        let vk = VerifierSRS::<E> {
            n: n,
            g: self.g_alpha_powers[0].into_projective(),
            h: self.h_alpha_powers[0].into_projective(),
            g_alpha: self.g_alpha_powers[1].into_projective(),
            g_beta: self.g_beta_powers[1].into_projective(),
            h_alpha: self.h_alpha_powers[1].into_projective(),
            h_beta: self.h_beta_powers[1].into_projective(),
        };
        (pk, vk)
    }

    pub fn write<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        (self.g_alpha_powers.len() as u32).serialize(&mut writer)?;
        write_vec(
            &mut writer,
            &self
                .g_alpha_powers
                .iter()
                .map(|e| e.into_projective())
                .collect::<Vec<E::G1Projective>>(),
        )?;
        write_vec(
            &mut writer,
            &self
                .g_beta_powers
                .iter()
                .map(|e| e.into_projective())
                .collect::<Vec<E::G1Projective>>(),
        )?;
        write_vec(
            &mut writer,
            &self
                .h_alpha_powers
                .iter()
                .map(|e| e.into_projective())
                .collect::<Vec<E::G2Projective>>(),
        )?;
        write_vec(
            &mut writer,
            &self
                .h_beta_powers
                .iter()
                .map(|e| e.into_projective())
                .collect::<Vec<E::G2Projective>>(),
        )?;
        Ok(())
    }

    /// Returns the hash over all powers of this generic srs.
    pub fn hash(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.write(&mut v).expect("failed to compute hash");
        Sha256::digest(&v).to_vec()
    }

    pub fn read<R: Read>(mut reader: R) -> Result<Self, Error> {
        let len = u32::deserialize(&mut reader).map_err(|e| Error::Serialization(e))?;
        if len > MAX_SRS_SIZE as u32 {
            return Err(Error::InvalidSRS("SRS len > maximum".to_string()));
        }

        let g_alpha_powers = read_vec(len, &mut reader).map_err(|e| Error::Serialization(e))?;
        let g_beta_powers = read_vec(len, &mut reader).map_err(|e| Error::Serialization(e))?;
        let h_alpha_powers = read_vec(len, &mut reader).map_err(|e| Error::Serialization(e))?;
        let h_beta_powers = read_vec(len, &mut reader).map_err(|e| Error::Serialization(e))?;

        Ok(Self {
            g_alpha_powers,
            g_beta_powers,
            h_alpha_powers,
            h_beta_powers,
        })
    }
}

/// Generates a SRS of the given size. It must NOT be used in production, only
/// in testing, as this is insecure given we know the secret exponent of the SRS.
pub fn setup_fake_srs<E: PairingEngine, R: Rng>(rng: &mut R, size: usize) -> GenericSRS<E> {
    let alpha = E::Fr::rand(rng);
    let beta = E::Fr::rand(rng);
    let g = E::G1Projective::prime_subgroup_generator();
    let h = E::G2Projective::prime_subgroup_generator();

    let mut g_alpha_powers = Vec::new();
    let mut g_beta_powers = Vec::new();
    let mut h_alpha_powers = Vec::new();
    let mut h_beta_powers = Vec::new();
    rayon::scope(|s| {
        let alpha = &alpha;
        let h = &h;
        let g = &g;
        let beta = &beta;
        let g_alpha_powers = &mut g_alpha_powers;
        s.spawn(move |_| {
            *g_alpha_powers = structured_generators_scalar_power(2 * size, g, alpha);
        });
        let g_beta_powers = &mut g_beta_powers;
        s.spawn(move |_| {
            *g_beta_powers = structured_generators_scalar_power(2 * size, g, beta);
        });

        let h_alpha_powers = &mut h_alpha_powers;
        s.spawn(move |_| {
            *h_alpha_powers = structured_generators_scalar_power(2 * size, h, alpha);
        });

        let h_beta_powers = &mut h_beta_powers;
        s.spawn(move |_| {
            *h_beta_powers = structured_generators_scalar_power(2 * size, h, beta);
        });
    });

    debug_assert!(h_alpha_powers[0] == E::G2Affine::prime_subgroup_generator());
    debug_assert!(h_beta_powers[0] == E::G2Affine::prime_subgroup_generator());
    debug_assert!(g_alpha_powers[0] == E::G1Affine::prime_subgroup_generator());
    debug_assert!(g_beta_powers[0] == E::G1Affine::prime_subgroup_generator());
    GenericSRS {
        g_alpha_powers,
        g_beta_powers,
        h_alpha_powers,
        h_beta_powers,
    }
}

pub(crate) fn structured_generators_scalar_power<G: ProjectiveCurve>(
    num: usize,
    g: &G,
    s: &G::ScalarField,
) -> Vec<G::Affine> {
    assert!(num > 0);
    let mut powers_of_scalar = Vec::with_capacity(num);
    let mut pow_s = G::ScalarField::one();
    for _ in 0..num {
        powers_of_scalar.push(pow_s);
        pow_s.mul_assign(s);
    }
    let scalar_bits = G::ScalarField::size_in_bits();
    let window_size = FixedBaseMSM::get_mul_window_size(num);
    let g_table = FixedBaseMSM::get_window_table::<G>(scalar_bits, window_size, g.clone());
    let powers_of_g = FixedBaseMSM::multi_scalar_mul::<G>(
        //let powers_of_g = msm::fixed_base::multi_scalar_mul::<G>(
        scalar_bits,
        window_size,
        &g_table,
        &powers_of_scalar[..],
    );
    powers_of_g.into_iter().map(|v| v.into_affine()).collect()
}

fn write_vec<G: ProjectiveCurve, W: Write>(mut w: W, v: &[G]) -> Result<(), SerializationError> {
    for p in v {
        p.serialize(&mut w)?;
    }
    Ok(())
}

fn read_vec<G: CanonicalDeserialize, R: Read>(
    len: u32,
    mut r: R,
) -> Result<Vec<G>, SerializationError> {
    (0..len).map(|_| G::deserialize(&mut r)).collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381 as Bls12;
    use rand_core::SeedableRng;
    use std::io::Cursor;

    #[test]
    fn test_srs_invalid_length() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(0u64);
        let size = 8;
        let srs = setup_fake_srs::<Bls12, _>(&mut rng, size);
        let vec_len = srs.g_alpha_powers.len();
        let mut buffer = Vec::new();
        srs.write(&mut buffer).expect("writing to buffer failed");
        // tryingout normal operations
        GenericSRS::<Bls12>::read(&mut Cursor::new(&buffer)).expect("can't read the srs");

        // trying to read the first size
        let read_size = u32::deserialize(Cursor::new(&buffer)).unwrap() as usize;
        assert_eq!(vec_len, read_size);

        // remove the previous size from the bufer - u32 = 4 bytes
        // and replace the size by appending the rest
        let mut new_buffer = Vec::new();
        let invalid_size = MAX_SRS_SIZE + 1;
        (invalid_size as u32)
            .serialize(&mut new_buffer)
            .expect("failed to write invalid size");
        buffer.drain(0..4);
        new_buffer.append(&mut buffer);
        GenericSRS::<Bls12>::read(&mut Cursor::new(&new_buffer))
            .expect_err("this should have failed");
    }
}
