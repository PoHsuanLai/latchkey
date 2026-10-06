//! A minimal agent, and the client that finds it. Run two of these and watch one win.
//!
//! ```text
//! cargo run --example agent -- serve   # becomes the agent, or says one already is
//! cargo run --example agent -- ask     # reaches it, starting one if nobody answers
//! ```
//!
//! It is also what `tests/across_processes.rs` drives, because the crate's central claim — that
//! a killed agent locks nobody out — is about *processes*, and cannot be shown inside one.

include!("../tests/support/agent.rs");
