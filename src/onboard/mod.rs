//! First-run agent provisioning (Mode A bootstrap + Mode C install pack).
//!
//! ## Subcommands
//!
//! * `init --install-pack <path>` — offline (Mode C); parse the operator's
//!   install pack, generate per-agent keypairs, persist state.
//! * `init --bootstrap --platform-url ... --onboard-token ... --platform-cert-pin ...`
//!   — online (Mode A); fetches an install pack from the platform.  The
//!   actual HTTP call lives in C1-Agent-2; this PR only wires the CLI plumbing.

pub mod bootstrap;
pub mod init;
pub mod install_pack;
pub mod rotate;

#[allow(unused_imports)]
pub use bootstrap::{run_bootstrap, BootstrapError};
#[allow(unused_imports)]
pub use init::{default_state_dir, run_init_install_pack, InitError};
#[allow(unused_imports)]
pub use install_pack::{load_install_pack, parse_install_pack, InstallPack, InstallPackError};
#[allow(unused_imports)]
pub use rotate::{run_rotate_keys, RotateError, RotationReport};
