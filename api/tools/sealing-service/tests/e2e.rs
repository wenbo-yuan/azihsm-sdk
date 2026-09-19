// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end integration tests for `azihsm-sealing-service`.
//!
//! Each command in the sealing-service CLI is a distinct OS process that
//! exchanges state through a single-file workspace container selected by the
//! `AZIHSM_SEALING_STATE_PATH` environment variable, mirroring the multi-VM
//! reality on hardware. These tests drive the *built binary* the same way —
//! one `std::process::Command` spawn per command, each pointed at the same
//! state file via the env var — so they exercise the real cross-process split
//! flow rather than in-process helpers.
//!
//! The whole suite is gated on the `emu` feature: only the emulator flavor can
//! run without physical HSM hardware, and the identity-injection layer makes
//! the emu partition identity byte-stable across processes so the split flow
//! behaves like hardware. Built without `--features emu`, this file compiles to
//! an empty test crate.
//!
//! Run with:
//! ```bash
//! cargo test -p azihsm_sealing_service --features emu
//! ```

#![cfg(feature = "emu")]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use serde_json::Value;

/// Monotonic counter to keep concurrent test state files unique.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A disposable, uniquely-named single-file workspace container for one test,
/// plus helpers to spawn the built CLI against it. Dropped at end of test: the
/// state file is removed.
struct TestWs {
    state_file: PathBuf,
}

impl TestWs {
    /// Reserve a fresh, unique state-file path under the system temp dir. The
    /// file itself is created lazily by the first command that writes state.
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let state_file = std::env::temp_dir().join(format!(
            "azihsm-sealing-e2e-{}-{n}-{nanos}.bin",
            std::process::id()
        ));
        Self { state_file }
    }

    /// Spawn the built binary with the given subcommand args, pointing it at
    /// this test's state file via `AZIHSM_SEALING_STATE_PATH`, returning the
    /// raw process output.
    fn raw(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_azihsm-sealing-service"))
            .env("AZIHSM_SEALING_STATE_PATH", &self.state_file)
            .args(args)
            .output()
            .expect("spawn azihsm-sealing-service")
    }

    /// Run a command, assert it succeeded, and return its stdout.
    fn run(&self, args: &[&str]) -> String {
        let out = self.raw(args);
        assert!(
            out.status.success(),
            "command {args:?} failed: status={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Run a command, assert it *failed*, and return its stderr (the CLI prints
    /// `error: <message>` to stderr and exits non-zero on any handler error).
    fn run_expect_fail(&self, args: &[&str]) -> String {
        let out = self.raw(args);
        assert!(
            !out.status.success(),
            "command {args:?} unexpectedly succeeded\n--- stdout ---\n{}",
            String::from_utf8_lossy(&out.stdout),
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    /// Decode the single-file workspace container into a map of POSIX-relative
    /// path -> file bytes. Returns an empty map when the state file does not
    /// yet exist (no command has written state).
    ///
    /// Mirrors the framing written by `src/container.rs`:
    /// `magic(8) | count(u32 LE) | [ path_len(u32 LE) | path | data_len(u64 LE) | data ]*`.
    fn decode(&self) -> BTreeMap<String, Vec<u8>> {
        let bytes = match std::fs::read(&self.state_file) {
            Ok(b) => b,
            Err(_) => return BTreeMap::new(),
        };
        let mut map = BTreeMap::new();

        let take = |pos: &mut usize, n: usize| -> Vec<u8> {
            assert!(*pos + n <= bytes.len(), "truncated container");
            let slice = bytes[*pos..*pos + n].to_vec();
            *pos += n;
            slice
        };

        assert!(bytes.len() >= 12, "container too short");
        assert_eq!(&bytes[0..8], b"AZSDBIN1", "bad container magic");
        let mut pos = 8usize;
        let count = u32::from_le_bytes(
            take(&mut pos, 4)
                .as_slice()
                .try_into()
                .expect("count bytes"),
        );
        for _ in 0..count {
            let path_len = u32::from_le_bytes(
                take(&mut pos, 4)
                    .as_slice()
                    .try_into()
                    .expect("path_len bytes"),
            ) as usize;
            let path = String::from_utf8(take(&mut pos, path_len)).expect("utf8 path");
            let data_len = u64::from_le_bytes(
                take(&mut pos, 8)
                    .as_slice()
                    .try_into()
                    .expect("data_len bytes"),
            ) as usize;
            let data = take(&mut pos, data_len);
            map.insert(path, data);
        }
        map
    }

    /// True when a workspace-relative path exists inside the container.
    fn exists(&self, rel: &str) -> bool {
        self.decode().contains_key(rel)
    }

    /// Parse a workspace-relative JSON manifest from the container.
    fn read_json(&self, rel: &str) -> Value {
        let map = self.decode();
        let bytes = map
            .get(rel)
            .unwrap_or_else(|| panic!("missing {rel} in container"));
        serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("parse {rel}: {e}"))
    }

    /// Byte length of a workspace-relative file inside the container.
    fn file_len(&self, rel: &str) -> u64 {
        let map = self.decode();
        map.get(rel)
            .map(|b| b.len() as u64)
            .unwrap_or_else(|| panic!("stat {rel}"))
    }
}

impl Drop for TestWs {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.state_file);
    }
}

/// Provision a partition with a fresh authority set, a sealing key, and a key
/// report (evidence bundle). Returns nothing; the artifacts live in `ws`.
fn provision_partition_new_authority(
    ws: &TestWs,
    partition: &str,
    authority_set: &str,
    sealing_key: &str,
    report: &str,
) {
    ws.run(&[
        "create_partition",
        "--partition",
        partition,
        "--new-authority-set",
        authority_set,
    ]);
    provision_key_and_report(ws, partition, sealing_key, report);
}

/// Provision a partition that reuses an existing authority set, then a sealing
/// key and key report. The shared policy is loaded from the workspace
/// container (no external `--policy` file).
fn provision_partition_reuse_authority(
    ws: &TestWs,
    partition: &str,
    authority_set: &str,
    sealing_key: &str,
    report: &str,
) {
    ws.run(&[
        "create_partition",
        "--partition",
        partition,
        "--authority-set",
        authority_set,
    ]);
    provision_key_and_report(ws, partition, sealing_key, report);
}

fn provision_key_and_report(ws: &TestWs, partition: &str, sealing_key: &str, report: &str) {
    ws.run(&[
        "create_sd_sealing_key",
        "--partition",
        partition,
        "--sealing-key",
        sealing_key,
    ]);
    ws.run(&[
        "key_report",
        "--partition",
        partition,
        "--sealing-key",
        sealing_key,
        "--report",
        report,
    ]);
}

/// Full cross-partition remote-backup round trip across eight separate
/// processes: two partitions on a shared authority set, sealing keys and key
/// reports on both, `create_sd` on the backing partition addressing the
/// receiver, then `restore_remote_backup` on the receiver joining the domain.
#[test]
fn full_remote_backup_round_trip() {
    let ws = TestWs::new();

    provision_partition_new_authority(&ws, "part-a", "auth-a", "ska", "repa");
    provision_partition_reuse_authority(&ws, "part-b", "auth-a", "skb", "repb");

    // Backing partition A creates the domain, addressed to receiver B.
    let create = ws.run(&[
        "create_sd",
        "--partition",
        "part-a",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "ska",
        "--receiver-evidence",
        "part-b/skb/repb",
    ]);
    assert!(
        create.contains("cross-partition"),
        "expected cross-partition scope, got:\n{create}"
    );
    // Before B restores, the outbound hand-off exists and B is not yet a member.
    assert!(ws.exists("secure-domains/sd-x/remote-backups/part-b.bin"));
    assert!(!ws.exists("secure-domains/sd-x/members/part-b/member.json"));

    // Receiver B joins the domain using A's sender evidence.
    let restore = ws.run(&[
        "restore_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
    ]);
    assert!(
        restore.contains("joined `sd-x`"),
        "expected join summary, got:\n{restore}"
    );

    // B's member area is now materialized with both recovery artifacts.
    assert!(ws.exists("secure-domains/sd-x/members/part-b/pok-local-backup.bin"));
    assert!(ws.exists("secure-domains/sd-x/members/part-b/sd-mk-backup.bin"));

    // B's member manifest records the remote-restore lineage.
    let member = ws.read_json("secure-domains/sd-x/members/part-b/member.json");
    assert_eq!(member["role"], "member");
    assert_eq!(member["joined_via"], "restore_remote_backup");
    assert_eq!(member["source_partition"], "part-a");

    // The secure-domain manifest now lists both partitions and the hand-off is
    // consumed.
    let domain = ws.read_json("secure-domains/sd-x/secure-domain.json");
    let members = domain["members"].as_array().expect("members array");
    assert_eq!(members.len(), 2, "domain should have two members");
    let roles: Vec<(&str, &str)> = members
        .iter()
        .map(|m| {
            (
                m["partition"].as_str().unwrap_or_default(),
                m["role"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert!(roles.contains(&("part-a", "backing")));
    assert!(roles.contains(&("part-b", "member")));
    let handoffs = domain["handoffs"].as_array().expect("handoffs array");
    assert_eq!(handoffs.len(), 1);
    assert_eq!(handoffs[0]["destination"], "part-b");
    assert_eq!(handoffs[0]["consumed"], true);

    // B's partition manifest now records domain membership.
    let part_b = ws.read_json("partitions/part-b/partition.json");
    assert_eq!(part_b["secure_domain"], "sd-x");

    // Re-running the restore is rejected: B already belongs to the domain.
    let err = ws.run_expect_fail(&[
        "restore_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
    ]);
    assert!(
        err.contains("already belongs to secure domain"),
        "expected already-a-member rejection, got:\n{err}"
    );
}

/// A self-backup names the backing partition as its own receiver: the domain
/// has a single (backing) member and its hand-off is immediately consumed.
#[test]
fn self_backup_single_partition() {
    let ws = TestWs::new();

    provision_partition_new_authority(&ws, "solo", "auth-solo", "sk", "rep");

    let create = ws.run(&[
        "create_sd",
        "--partition",
        "solo",
        "--secure-domain",
        "sd-solo",
        "--sealing-key",
        "sk",
        "--receiver-evidence",
        "solo/sk/rep",
    ]);
    assert!(
        create.contains("(self)"),
        "expected self scope, got:\n{create}"
    );

    let domain = ws.read_json("secure-domains/sd-solo/secure-domain.json");
    assert_eq!(domain["backup_scope"], "self");
    let members = domain["members"].as_array().expect("members array");
    assert_eq!(members.len(), 1, "self-backup domain has a single member");
    assert_eq!(members[0]["partition"], "solo");
    assert_eq!(members[0]["role"], "backing");
    let handoffs = domain["handoffs"].as_array().expect("handoffs array");
    assert_eq!(handoffs.len(), 1);
    assert_eq!(
        handoffs[0]["consumed"], true,
        "self-backup hand-off is consumed on creation"
    );

    // A backing partition already in a domain cannot back another one.
    let err = ws.run_expect_fail(&[
        "create_sd",
        "--partition",
        "solo",
        "--secure-domain",
        "sd-other",
        "--sealing-key",
        "sk",
        "--receiver-evidence",
        "solo/sk/rep",
    ]);
    assert!(
        err.contains("already belongs to secure domain"),
        "expected already-in-domain rejection, got:\n{err}"
    );
}

/// `restore_remote_backup` requires an existing domain with an outstanding
/// hand-off addressed to the receiver. With no such domain it must fail rather
/// than partially mutating state.
#[test]
fn restore_without_domain_is_rejected() {
    let ws = TestWs::new();

    provision_partition_new_authority(&ws, "part-a", "auth-a", "ska", "repa");
    provision_partition_reuse_authority(&ws, "part-b", "auth-a", "skb", "repb");

    // No `create_sd` has run, so domain `ghost` does not exist.
    let err = ws.run_expect_fail(&[
        "restore_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "ghost",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
    ]);
    assert!(
        !ws.exists("secure-domains/ghost/members/part-b/member.json"),
        "no member area should be created on failure"
    );
    let part_b = ws.read_json("partitions/part-b/partition.json");
    assert!(
        part_b["secure_domain"].is_null(),
        "part-b must not record membership after a failed restore, got:\n{err}"
    );
}

/// `restore_local_backup` refreshes a member's own device-local recovery pair
/// in place: no sealing key, evidence, or policy. Running it keeps the member
/// manifest and its on-disk artifacts consistent (verified by a second run,
/// which re-reads and re-verifies the refreshed pair), and a non-member
/// partition cannot self-restore.
#[test]
fn restore_local_backup_refreshes_recovery_pair() {
    let ws = TestWs::new();

    provision_partition_new_authority(&ws, "solo", "auth-solo", "sk", "rep");
    ws.run(&[
        "create_sd",
        "--partition",
        "solo",
        "--secure-domain",
        "sd-solo",
        "--sealing-key",
        "sk",
        "--receiver-evidence",
        "solo/sk/rep",
    ]);

    let out = ws.run(&[
        "restore_local_backup",
        "--partition",
        "solo",
        "--secure-domain",
        "sd-solo",
    ]);
    assert!(
        out.contains("refreshed `solo`"),
        "expected refresh summary, got:\n{out}"
    );

    // The member manifest's recorded artifact lengths match the refreshed files
    // on disk.
    let member = ws.read_json("secure-domains/sd-solo/members/solo/member.json");
    let artifacts = member["artifacts"].as_array().expect("artifacts array");
    assert_eq!(artifacts.len(), 2);
    for artifact in artifacts {
        let name = artifact["name"].as_str().expect("artifact name");
        let recorded = artifact["length"].as_u64().expect("artifact length");
        let actual = ws.file_len(&format!("secure-domains/sd-solo/members/solo/{name}"));
        assert_eq!(
            recorded, actual,
            "artifact `{name}` length drift after refresh"
        );
    }

    // A second refresh re-reads and re-verifies the freshly written pair; it
    // only succeeds if the in-place update kept manifest and files consistent.
    ws.run(&[
        "restore_local_backup",
        "--partition",
        "solo",
        "--secure-domain",
        "sd-solo",
    ]);

    // A partition that belongs to no domain cannot self-restore.
    ws.run(&[
        "create_partition",
        "--partition",
        "loner",
        "--new-authority-set",
        "auth-loner",
    ]);
    let err = ws.run_expect_fail(&[
        "restore_local_backup",
        "--partition",
        "loner",
        "--secure-domain",
        "sd-solo",
    ]);
    assert!(
        err.contains("does not belong to any secure domain"),
        "expected non-member rejection, got:\n{err}"
    );
}

/// `reseal_remote_backup` re-wraps the domain's BKS3 from a member (B, which
/// joined via a remote restore) to a brand-new destination (C), producing a new
/// outstanding hand-off that C then consumes via its own `restore_remote_backup`
/// — the full A → B → C forwarding chain across separate processes.
#[test]
fn reseal_forwards_domain_to_third_partition() {
    let ws = TestWs::new();

    // Three partitions on one shared authority set.
    provision_partition_new_authority(&ws, "part-a", "auth-a", "ska", "repa");
    provision_partition_reuse_authority(&ws, "part-b", "auth-a", "skb", "repb");
    provision_partition_reuse_authority(&ws, "part-c", "auth-a", "skc", "repc");

    // A creates the domain for B; B joins.
    ws.run(&[
        "create_sd",
        "--partition",
        "part-a",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "ska",
        "--receiver-evidence",
        "part-b/skb/repb",
    ]);
    ws.run(&[
        "restore_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
    ]);

    // A partition with no inbound remote backup cannot reseal: A is the backing
    // member and holds no `remote-backups/part-a.bin`.
    let err = ws.run_expect_fail(&[
        "reseal_remote_backup",
        "--partition",
        "part-a",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "ska",
        "--sender-evidence",
        "part-b/skb/repb",
        "--receiver-evidence",
        "part-c/skc/repc",
    ]);
    assert!(
        err.contains("source remote backup"),
        "expected missing-source rejection, got:\n{err}"
    );
    assert!(
        !ws.exists("secure-domains/sd-x/remote-backups/part-c.bin"),
        "failed reseal must not create a hand-off"
    );

    // B reseals the domain to C. The source evidence authenticates the origin
    // of B's inbound backup (A); the receiver evidence is C's.
    let reseal = ws.run(&[
        "reseal_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
        "--receiver-evidence",
        "part-c/skc/repc",
    ]);
    assert!(
        reseal.contains("resealed `sd-x` to `part-c`"),
        "expected reseal summary, got:\n{reseal}"
    );

    // The reseal produced an outstanding hand-off for C, sourced by B; C is not
    // yet a member.
    assert!(ws.exists("secure-domains/sd-x/remote-backups/part-c.bin"));
    let domain = ws.read_json("secure-domains/sd-x/secure-domain.json");
    assert_eq!(
        domain["members"].as_array().expect("members").len(),
        2,
        "C is not a member until it restores"
    );
    let c_handoff = domain["handoffs"]
        .as_array()
        .expect("handoffs")
        .iter()
        .find(|h| h["destination"] == "part-c")
        .expect("hand-off for part-c");
    assert_eq!(c_handoff["consumed"], false);
    assert_eq!(c_handoff["source_partition"], "part-b");
    assert_eq!(c_handoff["created_by"], "reseal_remote_backup");

    // C consumes the reseal output (sealed to C, sourced by B).
    let restore = ws.run(&[
        "restore_remote_backup",
        "--partition",
        "part-c",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skc",
        "--sender-evidence",
        "part-b/skb/repb",
    ]);
    assert!(
        restore.contains("joined `sd-x`"),
        "expected join summary, got:\n{restore}"
    );

    // The domain now has all three partitions; C's lineage points back to B.
    let domain = ws.read_json("secure-domains/sd-x/secure-domain.json");
    let members = domain["members"].as_array().expect("members");
    assert_eq!(members.len(), 3);
    let roles: Vec<(&str, &str)> = members
        .iter()
        .map(|m| {
            (
                m["partition"].as_str().unwrap_or_default(),
                m["role"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert!(roles.contains(&("part-a", "backing")));
    assert!(roles.contains(&("part-b", "member")));
    assert!(roles.contains(&("part-c", "member")));
    let c_member = ws.read_json("secure-domains/sd-x/members/part-c/member.json");
    assert_eq!(c_member["joined_via"], "restore_remote_backup");
    assert_eq!(c_member["source_partition"], "part-b");
    let part_c = ws.read_json("partitions/part-c/partition.json");
    assert_eq!(part_c["secure_domain"], "sd-x");

    // Resealing again to C is now rejected: C is already a member.
    let err = ws.run_expect_fail(&[
        "reseal_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
        "--receiver-evidence",
        "part-c/skc/repc",
    ]);
    assert!(
        err.contains("already a member"),
        "expected already-a-member rejection, got:\n{err}"
    );
}

/// The peer-backup pair: an existing member (B) hands the domain's BKS3 to a
/// peer (C) sealed to C's attested key, and C joins by consuming that peer
/// hand-off via `restore_peer_backup`. Exercises `create_peer_backup` +
/// `restore_peer_backup` across separate processes.
#[test]
fn peer_backup_admits_new_member() {
    let ws = TestWs::new();

    provision_partition_new_authority(&ws, "part-a", "auth-a", "ska", "repa");
    provision_partition_reuse_authority(&ws, "part-b", "auth-a", "skb", "repb");
    provision_partition_reuse_authority(&ws, "part-c", "auth-a", "skc", "repc");

    // A creates the domain for B; B joins as a member.
    ws.run(&[
        "create_sd",
        "--partition",
        "part-a",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "ska",
        "--receiver-evidence",
        "part-b/skb/repb",
    ]);
    ws.run(&[
        "restore_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
    ]);

    // A partition that is not a member cannot create a peer backup: C is not
    // yet in the domain.
    let err = ws.run_expect_fail(&[
        "create_peer_backup",
        "--partition",
        "part-c",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skc",
        "--peer-evidence",
        "part-b/skb/repb",
    ]);
    assert!(
        err.contains("is not a member"),
        "expected non-member rejection, got:\n{err}"
    );

    // Member B produces a peer backup addressed to C.
    let create = ws.run(&[
        "create_peer_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--peer-evidence",
        "part-c/skc/repc",
    ]);
    assert!(
        create.contains("handed `sd-x` to peer `part-c`"),
        "expected peer-backup summary, got:\n{create}"
    );

    // The peer hand-off exists and is outstanding, sourced by B; C is not yet a
    // member (peer hand-offs live under peer-backups/, not remote-backups/).
    assert!(ws.exists("secure-domains/sd-x/peer-backups/part-c.bin"));
    let domain = ws.read_json("secure-domains/sd-x/secure-domain.json");
    assert_eq!(domain["members"].as_array().expect("members").len(), 2);
    let c_handoff = domain["handoffs"]
        .as_array()
        .expect("handoffs")
        .iter()
        .find(|h| h["destination"] == "part-c")
        .expect("hand-off for part-c");
    assert_eq!(c_handoff["kind"], "peer");
    assert_eq!(c_handoff["consumed"], false);
    assert_eq!(c_handoff["source_partition"], "part-b");
    assert_eq!(c_handoff["created_by"], "create_peer_backup");

    // C consumes the peer hand-off (sealed to C, sourced by B) and joins.
    let restore = ws.run(&[
        "restore_peer_backup",
        "--partition",
        "part-c",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skc",
        "--peer-evidence",
        "part-b/skb/repb",
    ]);
    assert!(
        restore.contains("joined `sd-x`"),
        "expected join summary, got:\n{restore}"
    );

    // C is now a member with peer lineage back to B, and its member area holds
    // the recovered recovery pair.
    assert!(ws.exists("secure-domains/sd-x/members/part-c/pok-local-backup.bin"));
    assert!(ws.exists("secure-domains/sd-x/members/part-c/sd-mk-backup.bin"));
    let c_member = ws.read_json("secure-domains/sd-x/members/part-c/member.json");
    assert_eq!(c_member["role"], "member");
    assert_eq!(c_member["joined_via"], "restore_peer_backup");
    assert_eq!(c_member["source_partition"], "part-b");

    let domain = ws.read_json("secure-domains/sd-x/secure-domain.json");
    assert_eq!(domain["members"].as_array().expect("members").len(), 3);
    let c_handoff = domain["handoffs"]
        .as_array()
        .expect("handoffs")
        .iter()
        .find(|h| h["destination"] == "part-c")
        .expect("hand-off for part-c");
    assert_eq!(c_handoff["consumed"], true);
    let part_c = ws.read_json("partitions/part-c/partition.json");
    assert_eq!(part_c["secure_domain"], "sd-x");

    // Re-running the peer restore is rejected: C already belongs to the domain.
    let err = ws.run_expect_fail(&[
        "restore_peer_backup",
        "--partition",
        "part-c",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skc",
        "--peer-evidence",
        "part-b/skb/repb",
    ]);
    assert!(
        err.contains("already belongs to secure domain"),
        "expected already-a-member rejection, got:\n{err}"
    );
}

/// `show_partitions` renders a deterministically sorted per-partition table
/// that correlates each partition with its authority set, sealing keys, secure
/// domain, and role. A partition in no domain shows `-` for both domain columns.
#[test]
fn show_partitions_lists_domain_membership() {
    let ws = TestWs::new();

    // A backs a domain that B joins; C is provisioned but joins nothing.
    provision_partition_new_authority(&ws, "part-a", "auth-a", "ska", "repa");
    provision_partition_reuse_authority(&ws, "part-b", "auth-a", "skb", "repb");
    provision_partition_reuse_authority(&ws, "part-c", "auth-a", "skc", "repc");
    ws.run(&[
        "create_sd",
        "--partition",
        "part-a",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "ska",
        "--receiver-evidence",
        "part-b/skb/repb",
    ]);
    ws.run(&[
        "restore_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
    ]);

    let out = ws.run(&["show_partitions"]);
    let lines: Vec<&str> = out.lines().collect();

    // Header first, then partitions in sorted order.
    assert!(lines[0].starts_with("PARTITION"), "header row, got:\n{out}");
    let a = lines
        .iter()
        .position(|l| l.starts_with("part-a"))
        .expect("part-a row");
    let b = lines
        .iter()
        .position(|l| l.starts_with("part-b"))
        .expect("part-b row");
    let c = lines
        .iter()
        .position(|l| l.starts_with("part-c"))
        .expect("part-c row");
    assert!(a < b && b < c, "rows must be sorted, got:\n{out}");

    // A is the backing member of sd-x; B is a member; C belongs to no domain.
    assert!(
        lines[a].contains("auth-a") && lines[a].contains("sd-x") && lines[a].contains("backing"),
        "part-a row wrong:\n{}",
        lines[a]
    );
    assert!(
        lines[b].contains("sd-x") && lines[b].contains("member"),
        "part-b row wrong:\n{}",
        lines[b]
    );
    // The non-member row ends with two `-` columns (domain + role).
    assert!(
        lines[c].trim_end().ends_with('-') && !lines[c].contains("sd-x"),
        "part-c row should show no domain:\n{}",
        lines[c]
    );
}

/// `show_secure_domains` renders, per domain, the backing partition, each
/// member's join provenance, and the outstanding vs consumed hand-offs. An
/// outstanding reseal to a not-yet-joined partition appears as `outstanding`.
#[test]
fn show_secure_domains_renders_lineage() {
    let ws = TestWs::new();

    provision_partition_new_authority(&ws, "part-a", "auth-a", "ska", "repa");
    provision_partition_reuse_authority(&ws, "part-b", "auth-a", "skb", "repb");
    provision_partition_reuse_authority(&ws, "part-c", "auth-a", "skc", "repc");

    // A backs sd-x, B joins, then B reseals to C (outstanding, C not joined).
    ws.run(&[
        "create_sd",
        "--partition",
        "part-a",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "ska",
        "--receiver-evidence",
        "part-b/skb/repb",
    ]);
    ws.run(&[
        "restore_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
    ]);
    ws.run(&[
        "reseal_remote_backup",
        "--partition",
        "part-b",
        "--secure-domain",
        "sd-x",
        "--sealing-key",
        "skb",
        "--sender-evidence",
        "part-a/ska/repa",
        "--receiver-evidence",
        "part-c/skc/repc",
    ]);

    let out = ws.run(&["show_secure_domains"]);

    // Domain header names the domain and its backing partition.
    assert!(
        out.contains("SECURE DOMAIN  sd-x") && out.contains("backing part-a"),
        "domain header missing:\n{out}"
    );
    assert!(out.contains("members"), "members block missing:\n{out}");
    assert!(out.contains("hand-offs"), "hand-offs block missing:\n{out}");

    // Backing member is the root; B joined via a remote restore from A.
    assert!(
        out.contains("part-a  backing") && out.contains("(root)"),
        "backing/root line missing:\n{out}"
    );
    assert!(
        out.contains("part-b  member") && out.contains("<- part-a"),
        "member provenance missing:\n{out}"
    );

    // B's remote join is a consumed hand-off; the reseal to C is outstanding.
    assert!(
        out.contains("part-b") && out.contains("consumed"),
        "consumed hand-off missing:\n{out}"
    );
    assert!(
        out.contains("part-c") && out.contains("outstanding"),
        "outstanding hand-off missing:\n{out}"
    );
}
