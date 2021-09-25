[![CircleCI](https://circleci.com/gh/nikkolasg/snarkpack/tree/main.svg?style=svg)](https://circleci.com/gh/nikkolasg/snarkpack/tree/main)

# Snarpack on arkwork

This is a port in the arkwork framework of the original [implementation in bellperson](https://github.com/filecoin-project/bellperson/tree/master/src/groth16/aggregate) of [Snarkpack](https://eprint.iacr.org/2021/529.pdf). Note both works are derived from the original arkwork implementation of the inner pairing product argument (IPP) [paper](https://eprint.iacr.org/2019/1177.pdf).

## Dependency

Add the following to your `Cargo.toml`
```
snarkpack = { git = "https://github.com/nikkolasg/snarpack" }
```

## Usage

See the straightforward example in [`tests/aggregation.rs`](https://github.com/nikkolasg/snarkpack/blob/main/tests/aggregation.rs#L14).

## Contribution

There are plenty of issues to tackle so you're more than welcome to contribute.


