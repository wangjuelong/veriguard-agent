//! veriguard-implant subprocess manager.
//!
//! Used by the `command_inject` and `implant_drop` capabilities to drop a
//! short-lived process that performs the actual host-level work.  See
//! [`manager`] for the orchestration code and [`pipe`] for the
//! cross-platform named-pipe wrapper used to stream NDJSON results back to
//! the agent.

pub mod manager;
pub mod pipe;

#[allow(unused_imports)]
pub use manager::{ImplantError, ImplantManager};
#[allow(unused_imports)]
pub use pipe::{new_temp_pipe, NamedPipe};
