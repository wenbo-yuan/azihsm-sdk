// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compile-time flavor identity.
//!
//! One binary contains one flavor, fixed at build time by the `emu` Cargo
//! feature. There is no runtime backend selector.

/// Build flavor selected by Cargo features: `emu` when built with
/// `--features emu`, otherwise `hw`.
#[cfg(feature = "emu")]
pub const FLAVOR: &str = "emu";

/// Build flavor selected by Cargo features: `emu` when built with
/// `--features emu`, otherwise `hw`.
#[cfg(not(feature = "emu"))]
pub const FLAVOR: &str = "hw";

/// Version string reported by `--version`. It embeds the build flavor so a
/// caller can tell `emu` from `hw` even though both share the binary name.
#[cfg(feature = "emu")]
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (emu)");

/// Version string reported by `--version`. It embeds the build flavor so a
/// caller can tell `emu` from `hw` even though both share the binary name.
#[cfg(not(feature = "emu"))]
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (hw)");
