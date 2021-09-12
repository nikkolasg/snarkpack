use ark_serialize::SerializationError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("SRS size out of valid range")]
    InvalidSRSSize,

    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    #[error("Commitment key length invalid")]
    InvalidKeyLength,

    #[error("Vectors length do not match for inner product (IP)")]
    InvalidIPVectorLength,

    #[error("Invalid pairing result")]
    InvalidPairing,

    #[error("Proof Size Invalid")]
    InvalidProofSize,

    #[error("Proofs Not a power of two")]
    NotPowerOfTwo,

    #[error("Invalid SRS")]
    InvalidSRS,

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Malformed Groth16 verifying key")]
    MalformedVerifyingKey,
}
