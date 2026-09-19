// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Single-file workspace container.
//!
//! The sealing-service keeps all of its host-side state — partitions,
//! authority sets, secure domains, and hand-off blobs — in one flat binary
//! file rather than a directory tree. Each command process transparently
//! **unpacks** that file into a private scratch directory, runs the handler
//! against that scratch directory as its workspace root, and (on success)
//! **packs** the scratch directory back into the file.
//!
//! The container file location follows the same convention as the SDK test
//! MOBK cache (`AZIHSM_MOBK_PATH`): the `AZIHSM_SEALING_STATE_PATH` environment
//! variable names the file when set and non-empty; otherwise the default is
//! [`DEFAULT_STATE_FILE`] in the current working directory. A missing file is
//! treated as an empty workspace and is created on the first successful
//! command; an existing file is loaded and read.
//!
//! ## On-disk format
//!
//! A self-describing, dependency-free framing. All integers are little-endian.
//!
//! ```text
//! magic        : 8 bytes  = b"AZSDBIN1"
//! entry_count  : u32
//! repeated entry_count times, sorted by path:
//!   path_len   : u32          (UTF-8, workspace-relative, '/'-separated)
//!   path_bytes : path_len
//!   data_len   : u64
//!   data_bytes : data_len
//! ```
//!
//! Only files are stored; directories are implied by path prefixes and
//! recreated on unpack. Empty directories carry no workspace state and are not
//! preserved.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use crate::error::Error;
use crate::error::Result;

/// Environment variable naming the single-file workspace container.
pub const STATE_PATH_ENV: &str = "AZIHSM_SEALING_STATE_PATH";

/// Default container file name, resolved against the current working directory
/// when [`STATE_PATH_ENV`] is unset or empty.
pub const DEFAULT_STATE_FILE: &str = "azihsm-sealing-state.bin";

/// Container format magic. The trailing digit is the format version.
const MAGIC: &[u8; 8] = b"AZSDBIN1";

/// Resolve the workspace container path.
///
/// Uses [`STATE_PATH_ENV`] when set to a non-empty value; otherwise defaults to
/// [`DEFAULT_STATE_FILE`] under the current working directory.
pub fn resolve_state_path() -> PathBuf {
    match std::env::var(STATE_PATH_ENV) {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(DEFAULT_STATE_FILE),
    }
}

/// A private scratch directory that is removed when dropped.
///
/// Commands operate against this directory as their working root; it never
/// outlives the process and holds workspace bytes only for the duration of one
/// command.
pub struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    /// Create a fresh, uniquely named scratch directory under the system temp
    /// directory.
    pub fn new() -> Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "azihsm-sealing-scratch-{}-{nanos}",
            std::process::id()
        ));
        crate::util::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// The scratch directory root.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Serialize every file under `root` into a single container image.
///
/// Entries are emitted in sorted path order so the image is deterministic for
/// a given workspace state.
pub fn pack(root: &Path) -> Result<Vec<u8>> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    if root.exists() {
        collect(root, root, &mut entries)?;
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (path, data) in &entries {
        let path_bytes = path.as_bytes();
        out.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(path_bytes);
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }
    Ok(out)
}

/// Recreate the files described by `image` under `root`.
pub fn unpack(image: &[u8], root: &Path) -> Result<()> {
    let mut cursor = Cursor::new(image);

    let magic = cursor.take(MAGIC.len())?;
    if magic != MAGIC {
        return Err(Error::Internal(
            "workspace container has an unrecognized format header".to_owned(),
        ));
    }
    let count = cursor.take_u32()?;
    for _ in 0..count {
        let path_len = cursor.take_u32()? as usize;
        let path_bytes = cursor.take(path_len)?;
        let rel = std::str::from_utf8(path_bytes)
            .map_err(|_| Error::Internal("container entry path is not valid UTF-8".to_owned()))?;
        let data_len = usize::try_from(cursor.take_u64()?)
            .map_err(|_| Error::Internal("container entry length overflow".to_owned()))?;
        let data = cursor.take(data_len)?;

        let dest = resolve_under(root, rel)?;
        if let Some(parent) = dest.parent() {
            crate::util::create_dir_all(parent)?;
        }
        // All unpacked bytes are treated as secret-grade for scratch lifetime
        // (owner-only) regardless of their original per-file mode; the packed
        // container itself is written owner-only by the caller.
        crate::util::write_secret(&dest, data)?;
    }
    Ok(())
}

/// Recursively collect `(relative-posix-path, bytes)` for every file under
/// `dir`, relative to `root`.
fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    let read = fs::read_dir(dir).map_err(|source| Error::io("read directory", dir, source))?;
    for entry in read {
        let entry = entry.map_err(|source| Error::io("read directory entry", dir, source))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| Error::io("stat directory entry", &path, source))?;
        if file_type.is_dir() {
            collect(&path, root, out)?;
        } else if file_type.is_file() {
            let rel = relative_posix(root, &path)?;
            let bytes = fs::read(&path).map_err(|source| Error::io("read file", &path, source))?;
            out.push((rel, bytes));
        }
    }
    Ok(())
}

/// Convert an absolute path under `root` into a workspace-relative,
/// '/'-separated string.
fn relative_posix(root: &Path, abs: &Path) -> Result<String> {
    let rel = abs
        .strip_prefix(root)
        .map_err(|_| Error::Internal("packed path escaped the workspace root".to_owned()))?;
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            _ => {
                return Err(Error::Internal(
                    "packed path contains a non-normal component".to_owned(),
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

/// Resolve a container-relative path under `root`, rejecting absolute paths and
/// any `..`/root components that would escape the workspace.
fn resolve_under(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut dest = root.to_path_buf();
    for segment in rel.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(Error::Internal(format!(
                "container entry path `{rel}` is not a safe relative path"
            )));
        }
        dest.push(segment);
    }
    Ok(dest)
}

/// A minimal forward-only byte reader over the container image.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.bytes.len())
            .ok_or_else(|| Error::Internal("workspace container is truncated".to_owned()))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn take_u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A packed workspace round-trips back to the same files and bytes.
    #[test]
    fn pack_unpack_round_trips() {
        let src = Scratch::new().expect("scratch");
        crate::util::create_dir_all(&src.dir().join("partitions/p1")).expect("mkdir");
        crate::util::create_dir_all(&src.dir().join("partitions/p1/secrets")).expect("mkdir");
        crate::util::write_atomic(
            &src.dir().join("partitions/p1/partition.json"),
            b"{\"k\":1}",
        )
        .expect("write");
        crate::util::write_secret(&src.dir().join("partitions/p1/secrets/co.bin"), &[0xAB; 32])
            .expect("write secret");

        let image = pack(src.dir()).expect("pack");
        assert_eq!(&image[..8], MAGIC);

        let dst = Scratch::new().expect("scratch2");
        unpack(&image, dst.dir()).expect("unpack");

        let a = std::fs::read(dst.dir().join("partitions/p1/partition.json")).expect("read a");
        let b = std::fs::read(dst.dir().join("partitions/p1/secrets/co.bin")).expect("read b");
        assert_eq!(a, b"{\"k\":1}");
        assert_eq!(b, vec![0xAB; 32]);
    }

    /// An empty workspace packs to a header with zero entries and unpacks to
    /// nothing.
    #[test]
    fn empty_workspace_round_trips() {
        let src = Scratch::new().expect("scratch");
        let image = pack(src.dir()).expect("pack");
        let count = u32::from_le_bytes([image[8], image[9], image[10], image[11]]);
        assert_eq!(count, 0);

        let dst = Scratch::new().expect("scratch2");
        unpack(&image, dst.dir()).expect("unpack");
    }

    /// A truncated image is rejected rather than panicking.
    #[test]
    fn truncated_image_rejected() {
        let dst = Scratch::new().expect("scratch");
        assert!(unpack(b"AZSDBIN1\x01\x00\x00\x00", dst.dir()).is_err());
    }

    /// A path attempting to escape the root is rejected.
    #[test]
    fn escaping_path_rejected() {
        assert!(resolve_under(Path::new("/tmp/ws"), "../evil").is_err());
        assert!(resolve_under(Path::new("/tmp/ws"), "a/../b").is_err());
        assert!(resolve_under(Path::new("/tmp/ws"), "ok/child").is_ok());
    }
}
