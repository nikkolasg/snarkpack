use ark_ff::fields::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use merlin::Transcript as Merlin;
use std::io::Cursor;

trait Transcript<F: Field + CanonicalDeserialize> {
    fn domain_sep(&mut self);
    fn append<S: CanonicalSerialize>(&mut self, label: &str, point: &S);
    fn challenge_scalar(&mut self, label: &str) -> F;
}

impl<F> Transcript<F> for Merlin
where
    F: Field + CanonicalDeserialize,
{
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"groth16-aggregation-snarkpack");
    }

    fn append<S: CanonicalSerialize>(&mut self, label: &str, element: &S) {
        let mut buff: Vec<u8> = vec![0; element::serialized_size()];
        element.serialize(&mut buff);
        self.append_message(label.as_bytes(), &buff);
    }

    fn challenge_scalar(&mut self, label: &str) -> F {
        // Reduce a double-width scalar to ensure a uniform distribution
        let mut buf = [0; 128];
        self.challenge_bytes(label.as_bytes(), &mut buf);
        F::from_random_bytes(&buf).unwrap()
    }
}
