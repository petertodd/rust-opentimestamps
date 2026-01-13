//! An implementation of the OpenTimestamps protocol for Rust.
//!
//! This crate is a general purpose library for the creation and validation of OpenTimestamps
//! proofs.

#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]

pub mod op;
pub mod timestamp;
pub mod attestation;
pub mod tree;
pub mod rpc;

pub mod ser;
pub mod hex;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
