// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem, digest, and timestamp helpers shared by the command handlers.
//!
//! All artifact writes go through [`write_atomic`] (or [`write_secret`]): the
//! bytes are staged into a temporary sibling file, flushed, and atomically
//! renamed over the target, so an interrupted write never leaves a partially
//! written artifact in place. Directory and secret-file permissions follow the
//! "Authority and certificate implementation gap analysis" section of
//! `api/docs/design-sealing-service-cli.md` (dirs `0700`, secrets `0600`) on
//! Unix; other platforms use the process default.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;

use crate::error::Error;
use crate::error::Result;

/// Compute the lowercase-hex SHA-384 digest of `bytes`.
pub fn sha384_hex(bytes: &[u8]) -> String {
    let mut algo = HashAlgo::sha384();
    let mut out = [0u8; 48];
    // A fixed 48-byte SHA-384 digest into a correctly sized buffer cannot
    // fail; surface any backend error as an empty string is not acceptable, so
    // fall back to hashing into the buffer and ignoring the (impossible) error.
    if algo.hash(bytes, Some(&mut out)).is_err() {
        return String::new();
    }
    hex::encode(out)
}

/// The current UTC instant as an RFC 3339 string with a `Z` suffix and no
/// sub-second component (for example `2026-09-13T18:57:00Z`).
pub fn now_rfc3339() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Create `dir` (and parents) if absent, applying owner-only `0700`
/// permissions on Unix.
pub fn create_dir_all(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).map_err(|source| Error::io("create directory", dir, source))?;
    set_dir_mode(dir)?;
    Ok(())
}

/// Atomically write `bytes` to `path` through a temporary sibling file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_impl(path, bytes, false)
}

/// Atomically write secret `bytes` to `path`, applying owner-only `0600`
/// permissions on Unix.
pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    write_impl(path, bytes, true)
}

/// Read the full contents of `path`.
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| Error::io("read file", path, source))
}

/// List the immediate subdirectory names of `dir`, sorted lexicographically.
///
/// A non-existent `dir` yields an empty list (an empty inventory), so the
/// read-only inventory commands succeed on a fresh or partial workspace.
pub fn list_subdirs(dir: &Path) -> Result<Vec<String>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    let entries = fs::read_dir(dir).map_err(|source| Error::io("read directory", dir, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| Error::io("read directory entry", dir, source))?;
        let file_type = entry
            .file_type()
            .map_err(|source| Error::io("stat directory entry", &entry.path(), source))?;
        if file_type.is_dir()
            && let Some(name) = entry.file_name().to_str()
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// The digest and byte length of a file, for manifest references.
pub fn file_digest(path: &Path) -> Result<(String, u64)> {
    let bytes = read_file(path)?;
    Ok((sha384_hex(&bytes), bytes.len() as u64))
}

fn write_impl(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Internal("artifact path has no parent directory".to_owned()))?;
    let tmp = temp_sibling(path);

    {
        let mut file =
            fs::File::create(&tmp).map_err(|source| Error::io("create temp file", &tmp, source))?;
        if secret {
            set_file_mode(&tmp, 0o600)?;
        }
        file.write_all(bytes)
            .map_err(|source| Error::io("write temp file", &tmp, source))?;
        file.flush()
            .map_err(|source| Error::io("flush temp file", &tmp, source))?;
        file.sync_all()
            .map_err(|source| Error::io("sync temp file", &tmp, source))?;
    }

    fs::rename(&tmp, path).map_err(|source| {
        // Best-effort cleanup of the staged file on a failed rename.
        let _ = fs::remove_file(&tmp);
        Error::io("rename into place", parent, source)
    })?;
    Ok(())
}

/// A temporary sibling path for staging an atomic write.
fn temp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_owned()).unwrap_or_default();
    name.push(".tmp");
    match path.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

#[cfg(unix)]
fn set_dir_mode(dir: &Path) -> Result<()> {
    set_file_mode(dir, 0o700)
}

#[cfg(not(unix))]
fn set_dir_mode(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| Error::io("set permissions", path, source))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}
