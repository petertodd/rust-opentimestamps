//! An implementation of the OpenTimestamps protocol for Rust.
//!
//! This crate is a general purpose library for the creation and validation of OpenTimestamps
//! proofs.

pub mod op;
pub mod timestamp;
pub mod attestation;
pub mod tree;
pub mod rpc;

pub mod ser;
pub mod hex;
