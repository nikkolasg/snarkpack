#[macro_use]
mod macros;

mod commitment;
mod errors;
mod ip;
mod prover;
mod srs;

pub use errors::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
