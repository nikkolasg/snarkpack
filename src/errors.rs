use ark_serialize::SerializationError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    #[error("Commitment key length invalid")]
    InvalidKeyLength,

    #[error("Vectors length do not match for inner product (IP)")]
    InvalidIPVectorLength,

    #[error("Invalid pairing result")]
    InvalidPairing,

    #[error("Invalid SRS: {0}")]
    InvalidSRS(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Malformed Groth16 verifying key")]
    MalformedVerifyingKey,
}
