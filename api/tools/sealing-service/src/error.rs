// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error type for the sealing-service CLI.

use std::path::Path;
use std::path::PathBuf;

/// Errors surfaced by command dispatch and handlers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A command handler is not available in this flavor or not yet built.
    #[error("command not yet implemented: `{0}`")]
    NotImplemented(&'static str),

    /// A filesystem operation failed.
    #[error("failed to {action} `{path}`: {source}")]
    Io {
        /// The attempted action, for example `read file`.
        action: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// An artifact that must not already exist was found.
    #[error("{what} already exists: `{path}`")]
    AlreadyExists {
        /// A short description of the artifact.
        what: &'static str,
        /// Its path.
        path: PathBuf,
    },

    /// A required artifact was missing.
    #[error("{what} not found: `{path}`")]
    NotFound {
        /// A short description of the artifact.
        what: &'static str,
        /// Its path.
        path: PathBuf,
    },

    /// A user-supplied argument combination or value was invalid.
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    /// Reuse-mode validation found a mismatch between the supplied policy and
    /// the named authority set.
    #[error("policy does not match authority set: {0}")]
    PolicyMismatch(String),

    /// A cryptographic operation failed.
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// An HSM SDK operation failed.
    #[error("HSM operation failed during {op}: {detail}")]
    Hsm {
        /// The operation name.
        op: &'static str,
        /// A human-readable detail.
        detail: String,
    },

    /// A manifest could not be parsed or serialized.
    #[error("manifest error at `{path}`: {detail}")]
    Manifest {
        /// The manifest path.
        path: PathBuf,
        /// A human-readable detail.
        detail: String,
    },

    /// An evidence bundle could not be parsed or failed a consistency check.
    #[error("evidence bundle error: {0}")]
    Evidence(String),

    /// An internal invariant was violated.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Build an [`Error::Io`] from a failed filesystem action.
    pub fn io(action: &'static str, path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }

    /// Build an [`Error::Crypto`] from any displayable cause.
    pub fn crypto(detail: impl std::fmt::Display) -> Self {
        Self::Crypto(detail.to_string())
    }

    /// Build an [`Error::Hsm`] from any displayable cause.
    pub fn hsm(op: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::Hsm {
            op,
            detail: detail.to_string(),
        }
    }
}

/// Convenience result alias for CLI operations.
pub type Result<T> = std::result::Result<T, Error>;
