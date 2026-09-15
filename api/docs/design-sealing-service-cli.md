<!-- Copyright (c) Microsoft Corporation. All rights reserved. -->

# Sealing Service CLI design

## Goal

Define a command-line interface for sealing-service operations without relying
on an in-memory command chain or a JSON workflow configuration.

This document is a design proposal only. No CLI implementation should be
created until the command model, flavor behavior, persisted state, and
operation contracts are agreed.

The CLI is a single crate that produces one binary, `azihsm-sealing-service`.
Both flavors share the same binary name, source, and CLI surface; they differ
only by a compile-time Cargo feature. The `emu` flavor is built with
`--features emu`; the `hw` flavor is built without it (the default). The same
`azihsm-sealing-service` name is used for both artifacts, so a caller cannot
tell the flavor from the binary name alone; the flavor is fixed at build time
and reported by `azihsm-sealing-service --version`.

- The `emu` flavor enables the existing `emu` Cargo feature. The emulator has
  no partition that survives the CLI process. Each command
  that needs partition state, including the partition local masking key, must
  reconstruct that state with `part_init_ex` and `part_final_ex` before calling
  the requested API.
- The `hw` flavor is built without the `emu` feature and uses the platform DDI.
  Hardware retains its initialized partition across CLI processes. Commands
  after partition initialization use that persistent partition directly and
  call their requested API without repeating `part_init_ex` or
  `part_final_ex`.

Flavor selection happens at compile time via a Cargo feature; both flavors
build the same `azihsm-sealing-service` binary. One binary contains one flavor;
the CLI does not expose a runtime `--backend` selector.

## Terminology

- **Secure domain** — one recoverable key-material identity. Its root is a
  single BKS3 (the 48-byte partition-owner seed the firmware mints in
  `create_sd`). Every backup artifact this document names — the device-local
  recovery envelope, the outbound remote backup, a resealed remote backup, a
  peer backup — is a different masking or HPKE-sealed envelope of that **same
  BKS3**. Restore recovers the same BKS3; reseal re-wraps the same BKS3 to a new
  recipient. There is no versioning: one secure domain is one BKS3 for its whole
  lifetime, shown non-secretly by its policy SHA-384 and backing-partition PID
  (never by the BKS3 itself).
- **Backing partition** — the single partition named inside the policy as
  `backup_part_id`. It is the only partition allowed to run `create_sd` for the
  domain (firmware enforces `pid == backup_part_id` in
  `sd_create_remote_backup`). "Backing" is a policy fact, not a possession fact:
  even if wiped and rejoined, no other partition can become backing, because the
  identity is baked into the shared policy. Exactly one per domain.
- **Member partition** — any partition that currently holds the domain's BKS3,
  i.e. has an installed device-local recovery envelope. The backing partition is
  itself a member. Other partitions become members by **joining** — running
  `restore_remote_backup` or `restore_peer_backup` against an inbound backup
  sealed to them. Members grow over time; backing ⊆ members. A member that is
  not backing has `pid != backup_part_id`, which is fine because restore, reseal,
  and peer handlers never check `backup_part_id`.
- **Hand-off backup** — an outbound backup sealed to a *destination* partition
  that has not yet joined: the remote backup `create_sd` produces for its first
  receiver, a `reseal_remote_backup` output redirected to a new destination, or
  a `create_peer_backup` output for a peer. It carries the same BKS3, sealed to
  the destination's attested public key. The destination becomes a member only
  after it consumes the hand-off with the matching restore command.

## Command model

The executable syntax is the same for both flavors:

```text
azihsm-sealing-service --working-dir <path> <command> [command options]
```

Emulator partition replay is compiled only under `#[cfg(feature = "emu")]`.
The hardware flavor uses `#[cfg(not(feature = "emu"))]` paths and does not
contain a runtime branch that can invoke emulator replay.

Both compiled flavors expose the same CLI arguments. There are no
flavor-specific command-line options. The build selects the DDI backend;
`--working-dir` stores logical partition state for `emu` and host-visible
artifacts for `hw`.

The CLI uses SDK-style snake-case command names so each user-facing command
maps clearly to one sealing-service operation:

```text
create_partition
create_sd_sealing_key
key_report
create_sd
restore_local_backup
restore_remote_backup
reseal_remote_backup
create_peer_backup
restore_peer_backup
help
show_partitions
show_secure_domains
```

The initial example flow is:

```text
create_partition
-> create_sd_sealing_key
-> key_report
-> create_sd
```

Every arrow is a process boundary. In the `emu` flavor, every command after
`create_partition` identifies its target with `--partition`. This is the
logical workspace name whose persisted
`local_mk_backup` is used to reconstruct the partition local masking key. For
the `hw` flavor, the compiled DDI operates on the initialized hardware
partition. The hardware flavor still uses `--partition` to select the
host-side artifact directory created by `create_partition`, but that name does
not reload hardware device state.

## Command contracts

All commands take the global `--working-dir <path>` option before the command
name. Evidence arguments (`--receiver-evidence`, `--sender-evidence`,
`--peer-evidence`) are `<partition>/<key>/<report>` workspace references, not
filesystem paths. Backup inputs are resolved from fixed, role-named artifacts
under the named secure domain — a partition's own device-local recovery
envelope, or the hand-off backup addressed to it — never from a numbered
generation. There is no `--generation` selector, because a domain is one BKS3
with one set of role-named artifacts, not a version history. The policy is
never a command-line argument; it is loaded from the partition manifest.
Command outputs are the artifacts described in the workspace layout below.

| CLI command | SDK operation | Command-line arguments | Output artifacts |
|---|---|---|---|
| `create_partition` | `open_session_ex` (bootstrap, default PSK) + `change_psk` + close + `open_session_ex` (reopen, rotated PSK) + `part_init_ex` + `part_final_ex` | `--partition <name>` and either `--new-authority-set <name>` or `--authority-set <name> --policy <file>` | Initialized partition workspace: `secrets/co-psk.bin`, PID public key and three PID chains under `attestation/`, `recovery/{mach-seed.bin,part-final-local-mk-backup.bin}` (`emu`); new-mode also writes the authority set and `policy.bin` |
| `create_sd_sealing_key` | `SdSealingKeyGen` | `--partition <name> --sealing-key <new-key-name>` | `sealing-keys/<key>/{masked-key.bin,public-key.der}` |
| `key_report` | `KeyReport` | `--partition <name> --sealing-key <key-name> --report <report-name> [--report-data <file>]` | `sealing-keys/<key>/evidence/<report>.bin` (report embedded, no standalone `.cose`) |
| `create_sd` | `sd_create_remote_backup` | `--partition <backing> --secure-domain <new-domain> --sealing-key <backing-key> --receiver-evidence <ref>` | New `secure-domains/<domain>/` with `members/<backing>/{pok-local-backup,sd-mk-backup}.bin` and `remote-backups/<receiver>.bin` |
| `restore_local_backup` | `sd_restore_local_backup` | `--partition <name> --secure-domain <domain>` | Refreshed `members/<name>/{pok-local-backup,sd-mk-backup}.bin` (updated in place) |
| `restore_remote_backup` | `sd_restore_remote_backup` | `--partition <receiver> --secure-domain <domain> --sealing-key <receiver-key> --sender-evidence <ref>` | New `members/<receiver>/{pok-local-backup,sd-mk-backup}.bin`; consumed `remote-backups/<receiver>.bin` |
| `reseal_remote_backup` | `sd_reseal_remote_backup` | `--partition <name> --secure-domain <domain> --sealing-key <source-receiver-key> --sender-evidence <ref> --receiver-evidence <ref>` | New hand-off `remote-backups/<new-dest>.bin` |
| `create_peer_backup` | `sd_create_peer_backup` | `--partition <name> --secure-domain <domain> --sealing-key <sender-key> --peer-evidence <ref>` | New hand-off `peer-backups/<dest>.bin` |
| `restore_peer_backup` | `sd_restore_peer_backup` | `--partition <receiver> --secure-domain <domain> --sealing-key <receiver-key> --peer-evidence <ref>` | New `members/<receiver>/{pok-local-backup,sd-mk-backup}.bin`; consumed `peer-backups/<receiver>.bin` |
| `help` | none | `[<command>]` | Prints command usage to stdout; no files written |
| `show_partitions` | none | none (uses the global `--working-dir`) | Prints a per-partition table (authority set, sealing keys, secure domain, SD role) to stdout; no files written |
| `show_secure_domains` | none | none (uses the global `--working-dir`) | Prints per-secure-domain membership and hand-off lineage (backing partition, members, outbound hand-offs) to stdout; no files written |

`create_sd` is the user-facing name for the SDK's
`sd_create_remote_backup` operation. The SDK operation both creates the
security domain and returns its remote and device-local backup artifacts.

### `create_sd` command contract

```text
azihsm-sealing-service create_sd \
  --partition <sender-partition> \
  --secure-domain <new-domain-name> \
  --sealing-key <sender-key-name> \
  --receiver-evidence <partition-name>/<key-name>/<report-name>
```

Evidence arguments are workspace references, not unrestricted filesystem
paths. For example, `partition-b/key-b/report-1` resolves beneath the selected
working directory to:

```text
partitions/partition-b/sealing-keys/key-b/evidence/report-1.bin
```

Sender evidence is not a separate input to `create_sd`. `key_report` generates
evidence for a sealing key when needed for a later remote restore, reseal, or
peer operation. In a self-backup, the sender's own evidence is supplied in the
receiver-evidence role because sender and receiver are the same partition.

`--receiver-evidence` is always required, matching
`HsmSession::sd_create_remote_backup`. For a cross-partition backup it
references the destination receiver's evidence. For a self-backup it
references evidence generated from the selected sender partition and sealing
key. The CLI determines whether the operation is self or cross-partition by
comparing the evidence partition identity with `--partition`.

The policy is not a command-line argument. The CLI loads the exact policy
referenced by the sender's `partition.json`, verifies its recorded SHA-384
digest, and validates both evidence reports against those policy bytes.

Before invoking the one-shot HSM operation, the CLI:

1. Validates the sender partition and sealing-key manifests and their
   referenced files.
2. Resolves and validates receiver evidence when supplied.
3. Parses the receiver evidence certificates and COSE_Sign1 key report.
4. Confirms that the three chains in the bundle share the report-signing PID
   public key.
5. Confirms that the partition-owner chain anchors to the policy SATA.
6. Confirms that the v2 report binds to the exact policy digest.
7. Confirms that the secure-domain workspace does not exist and that the
   sender partition belongs to no secure domain.
8. Acquires the required workspace and partition locks and prepares the
   `members/<backing>/` and `remote-backups/` staging directories.

On success, `secure-domain.json` records:

- schema version and secure-domain name;
- backing partition name and PID;
- backing sealing-key name and public-key SHA-384 fingerprint;
- receiver partition name, PID, sealing-key fingerprint, evidence reference,
  and evidence SHA-384 digest;
- whether the backup is self or cross-partition;
- authority-set name;
- policy relative path and SHA-384 digest;
- members, initially containing only the backing partition; and
- creation timestamp.

For a cross-partition backup, the receiver is recorded as an outstanding
hand-off destination and becomes a member only after a successful remote
restore. For a self-backup, backing and receiver are the same partition, which
is the sole member and has no outstanding hand-off.

`HsmSdEvidence` consists of a manufacturer certificate chain, owner
certificate chain, partition-owner certificate chain, and key report.
After running `KeyReport`, `key_report` packages these four inputs into a
single serializable evidence bundle so evidence generated for one partition
can be supplied to operations on another partition. The key report is retained
only inside that bundle; no standalone COSE_Sign1 report file is written. The
bundle does not contain the sealing private key or any masking key.

No secure-domain command consumes a bare key report; every flow reads the
report through the `report` field of the evidence bundle. The embedded report
can be extracted for external attestation or inspection through
`show_secure_domains`, so the evidence bundle is the single persisted output of
`key_report`.

Both flavors use the same test-certificate path during `create_partition`.
After obtaining the active partition's PID public key, the command:

1. Generates a new test authority set or loads the requested existing set.
2. Uses each authority to issue a leaf certificate for that PID public key.
3. Builds and exports the three root-to-leaf PID certificate chains.
4. Generates a new policy from the authority set for the first partition, or
   validates and uses the supplied policy verbatim for an additional partition.

Public authority certificates are copied into each partition's attestation
artifacts. Reusable authority private keys are stored only in the named
authority set with secret-file permissions; they are never included in SD
evidence.

Each chain terminates in a leaf certificate for the same PID public key that
signs the key report, but each represents a different authority:

1. The test manufacturer authority issues the manufacturer PID chain.
2. The test owner authority issues the owner PID chain.
3. The test SATA issues the partition-owner PID chain. Its root public key
   matches the SATA public key in the generated unified partition policy.

The PTA CSR/report returned by `part_init_ex` and the POTA-to-PTA chain passed
to `part_final_ex` are separate partition-finalization artifacts; they do not
replace these three evidence chains.

After its HSM report operation, `key_report` loads the three chains from the
selected partition artifact directory and verifies that all four artifacts
(the three chain leaves plus the persisted PID public key) identify the same
PID public key. The report's policy binding is satisfied by construction: the
report is freshly generated on the just-reconstructed partition, which was
initialized with the recorded backing policy. Packaging the evidence requires
no additional HSM operation.

This per-partition authority generation is sufficient only for the initial
self-backup flow. A multi-partition secure domain requires a shared test
authority set and exact shared policy:

1. Every partition-owner chain must be issued by the SATA authority whose
   public key is embedded in the shared policy.
2. Each v2 key report used as sender or destination evidence must attest the
   SHA-384 hash of that exact policy.
3. The manufacturer and owner chains may have different self-signed roots;
   firmware validates those chains but does not anchor them to policy.

Therefore, independently generating a SATA authority for every partition
would make cross-partition remote restore and reseal fail evidence
verification. `create_partition` has two mutually exclusive trust modes:

```text
# First/backing partition: create the authority set and policy.
create_partition \
  --partition <name> \
  --new-authority-set <authority-set-name>

# Additional partition: reuse the authority set and exact policy.
create_partition \
  --partition <name> \
  --authority-set <authority-set-name> \
  --policy <path-to-policy.bin>
```

The reusable authority set contains the test manufacturer, owner, SATA, and
POTA authorities. SATA is needed to issue each partition's partition-owner
PID chain. POTA is also required because the exact shared policy contains its
public key and `part_final_ex` needs the corresponding authority to issue the
new partition's PTA chain. If SAPOTA is enabled in the policy, its authority
must be included as well.

Before initializing an additional partition, the CLI validates that the SATA,
POTA, and optional SAPOTA public keys in the authority set exactly match the
keys embedded in the supplied policy. The policy is then used verbatim; the
CLI must not regenerate it or replace its backing-partition identity fields.

### Cross-partition remote restore

For sender partition A and receiver partition B:

1. A and B are initialized against the same policy and SATA authority.
2. B generates sealing key B, key report B, and evidence B.
3. A runs `create_sd` with sealing key A and evidence B. The resulting
   `pok_remote_backup` is encrypted to B and authenticated by A.
4. B runs `restore_remote_backup` with sealing key B, evidence A, the same
   policy, `pok_remote_backup`, and `sd_mk_backup`.

### Cross-partition reseal

For a source backup from A to B that must be redirected to C:

1. B runs `reseal_remote_backup` with sealing key B, evidence A, evidence C,
   the same policy, and the source `pok_remote_backup`.
2. B opens the source backup using sealing key B and authenticates A through
   evidence A.
3. B reseals the recovered backup to C's attested sealing-key public key and
   authenticates the new backup with sealing key B.
4. C later runs `restore_remote_backup` using sealing key C and evidence B.
   It also receives the unchanged `sd_mk_backup` associated with the security
   domain.

All three partitions' partition-owner evidence chains must anchor to the same
SATA public key, and their evidence reports must bind to the same policy.

The evidence bundle is public attestation material. The SDK does not currently
define a persisted evidence serialization: `HsmSdEvidence` is only a borrowed
Rust structure containing three arrays of DER certificate slices and one
COSE_Sign1 byte slice. The DDI's out-of-band descriptors are an internal wire
transport and are not a file format.

The CLI stores evidence as a versioned `.bin` container. A raw concatenation is
not sufficient because certificate and report lengths are variable. Version 1
uses this canonical little-endian framing:

```text
magic:                  [u8; 8] = "AZSDEV01"
manufacturer chain:    chain
owner chain:           chain
partition-owner chain: chain
key report length:     u32
key report:            [u8; key report length]

chain:
  certificate count:   u16
  repeated certificate:
    certificate length: u32
    certificate DER:    [u8; certificate length]
```

Certificates are stored root-to-leaf, matching the current SDK tests. The
decoder rejects an incorrect magic value, zero-length fields, truncated or
trailing bytes, counts above the SDK evidence-chain limit, oversized lengths,
invalid DER certificates, and malformed COSE_Sign1 reports. Cryptographic
identity, chain, SATA-anchor, report-signature, and policy-binding checks are
performed before the bundle is accepted by `create_sd` or another SD command.

### `restore_local_backup` command contract

```text
azihsm-sealing-service restore_local_backup \
  --partition <partition-name> \
  --secure-domain <domain-name>
```

Maps to `HsmSession::sd_restore_local_backup(pok_local_backup, sd_mk_backup)`.
This is the self-recovery path: the operating partition is already a member of
the secure domain and refreshes its own device-local recovery point. It takes
no sealing key, no evidence, and no policy.

The CLI reads `pok_local_backup` and `sd_mk_backup` from the partition's own
member area, `members/<partition>/`. Before the one-shot HSM call it validates
that `--partition` is a recorded member of `--secure-domain`, that both source
blobs exist with matching manifest digests, and acquires the workspace and
partition locks.

On success it recovers the same BKS3 and re-masks it at the current
`{svn, owner}`, writing the refreshed `HsmSdRestoreResult` values back **in
place** over `members/<partition>/{pok-local-backup.bin,sd-mk-backup.bin}` (an
atomic replacement, not a new copy). No new domain or backup is minted; the BKS3
identity, policy binding, and membership are unchanged.

### `restore_remote_backup` command contract

```text
azihsm-sealing-service restore_remote_backup \
  --partition <receiver-partition> \
  --secure-domain <domain-name> \
  --sealing-key <receiver-key-name> \
  --sender-evidence <partition-name>/<key-name>/<report-name>
```

Maps to `HsmSession::sd_restore_remote_backup(masked_sealing_key,
sender_evidence, policy, src_remote_backup, prev_sd_mk_backup)`. It runs on the
receiver partition to admit it into a secure domain created for it by a remote
`create_sd`. The full flow is described under **Cross-partition remote
restore**.

`--sealing-key` selects the receiver's own masked sealing key; its attested
public key must match the receiver evidence used when the sender ran
`create_sd`. `--sender-evidence` references the sender's evidence bundle, which
authenticates the backup's origin. The policy is loaded from the receiver's
`partition.json`, not the command line.

The CLI reads `src_remote_backup` from the hand-off addressed to this receiver,
`remote-backups/<receiver>.bin`. `prev_sd_mk_backup` is required by the SDK
signature but has no prior member area on a first join; the CLI passes the
domain's current `sd_mk_backup` state per the SDK contract. Before the one-shot
HSM call it validates the receiver partition and sealing-key manifests;
resolves and cryptographically validates sender evidence (shared PID across its
three chains, partition-owner chain anchored to the policy SATA, report bound to
the exact policy digest); confirms the receiver is an outstanding hand-off
destination and not yet a member; and acquires the workspace and partition
locks.

On success the receiver recovers the **same BKS3** carried by the hand-off and
installs it locally: the CLI writes the refreshed `HsmSdRestoreResult` values to
a new `members/<receiver>/{pok-local-backup.bin,sd-mk-backup.bin}`, and marks
the consumed `remote-backups/<receiver>.bin` as joined. No new domain is minted.
`secure-domain.json` adds the receiver to `members` and clears its outstanding
hand-off.

### `reseal_remote_backup` command contract

```text
azihsm-sealing-service reseal_remote_backup \
  --partition <reseal-partition> \
  --secure-domain <domain-name> \
  --sealing-key <reseal-key-name> \
  --sender-evidence <partition-name>/<key-name>/<report-name> \
  --receiver-evidence <partition-name>/<key-name>/<report-name>
```

Maps to `HsmSession::sd_reseal_remote_backup(masked_sealing_key, src_evidence,
dest_evidence, policy, src_remote_backup)`. It runs on a partition that already
holds the secure domain (for example, the original receiver B) and produces a
new hand-off addressed to a new destination C. The full flow is described under
**Cross-partition reseal**.

`--sealing-key` selects the reseal partition's own masked sealing key, used to
open the source backup. `--sender-evidence` authenticates the source of the
backup being resealed; `--receiver-evidence` supplies the new destination's
attested public key, to which the backup is resealed. The policy is loaded from
the reseal partition's `partition.json`.

The CLI reads `src_remote_backup` from the hand-off this partition can open —
`remote-backups/<reseal-partition>.bin`. Before the one-shot HSM call it
validates the reseal partition and sealing-key manifests; resolves and
validates both source and destination evidence, confirming both partition-owner
chains anchor to the policy SATA and both reports bind to the exact policy
digest; confirms `--partition` is a member of the domain; and acquires the
locks.

The firmware HPKE-opens the source backup (recovering the **same BKS3**) and
HPKE-Auth-seals that same BKS3 to the destination. On success the CLI writes the
returned `Vec<u8>` as a new hand-off `remote-backups/<new-dest>.bin`. This is
the same domain/BKS3, re-wrapped to a new recipient — not a new domain and not a
new recovery point. `secure-domain.json` records the destination as an
outstanding hand-off; it becomes a member only after it runs
`restore_remote_backup`. C's `restore_remote_backup` must consume this reseal
output (sealed to C), not the original `create_sd` hand-off (sealed to B).

### `create_peer_backup` command contract

```text
azihsm-sealing-service create_peer_backup \
  --partition <partition-name> \
  --secure-domain <domain-name> \
  --sealing-key <sender-key-name> \
  --peer-evidence <partition-name>/<key-name>/<report-name>
```

Maps to `HsmSession::sd_create_peer_backup(masked_sealing_key, dst_evidence,
policy, pok_local_backup)`. It runs on an existing member partition and
produces a peer backup targeted at another partition within the same secure
domain, encrypted to that peer's attested public key and authenticated by the
operating partition's sealing key.

`--sealing-key` selects the operating partition's own masked sealing key.
`--peer-evidence` references the destination peer's evidence bundle. The policy
is loaded from the operating partition's `partition.json`.

The CLI reads `pok_local_backup` from the operating partition's own member area,
`members/<partition>/pok-local-backup.bin`. Before the one-shot HSM call it
validates the operating partition and sealing-key manifests; resolves and
validates peer evidence against the policy SATA and policy digest; confirms
`--partition` is a member of the domain; and acquires the locks.

On success the CLI writes the returned `Vec<u8>` — the **same BKS3** sealed to
the peer — as a new hand-off `peer-backups/<dest>.bin`. This is the same domain,
handed to a peer; no new domain or recovery point is minted. `secure-domain.json`
records the peer as an outstanding hand-off target; it becomes a member only
after it runs `restore_peer_backup`.

### `restore_peer_backup` command contract

```text
azihsm-sealing-service restore_peer_backup \
  --partition <receiver-partition> \
  --secure-domain <domain-name> \
  --sealing-key <receiver-key-name> \
  --peer-evidence <partition-name>/<key-name>/<report-name>
```

Maps to `HsmSession::sd_restore_peer_backup(masked_sealing_key, src_evidence,
policy, pok_peer_backup, prev_sd_mk_backup)`. It runs on the destination peer to
admit it into the secure domain from a peer backup produced by
`create_peer_backup`.

`--sealing-key` selects the receiving peer's own masked sealing key; its
attested public key must match the peer evidence used by `create_peer_backup`.
`--peer-evidence` references the source member's evidence bundle, which
authenticates the peer backup's origin. The policy is loaded from the receiving
peer's `partition.json`.

The CLI reads `pok_peer_backup` from the hand-off addressed to this peer,
`peer-backups/<receiver>.bin`; `prev_sd_mk_backup` is supplied per the SDK
contract. Before the one-shot HSM call it validates the receiving peer and
sealing-key manifests; resolves and validates source-peer evidence against the
policy SATA and policy digest; confirms the peer is an outstanding hand-off
target and not yet a member; and acquires the locks.

On success the peer recovers the **same BKS3** and installs it locally: the CLI
writes the refreshed `HsmSdRestoreResult` values to a new
`members/<receiver>/{pok-local-backup.bin,sd-mk-backup.bin}` and marks the
consumed `peer-backups/<receiver>.bin` as joined. `secure-domain.json` adds the
peer to `members` and clears its outstanding hand-off.

## Authority and certificate implementation gap analysis

The common authority-set flow is feasible for both `emu` and `hw`; it does not
depend on emulator state or hardware-specific key generation. Authority keys
and certificates are host artifacts used before or around the shared
`part_init_ex` / `part_final_ex` provisioning flow.

The following required primitives already exist as public SDK dependencies:

1. `azihsm_crypto::EccPrivateKey::from_curve(EccCurve::P384)` generates a
   cryptographically random P-384 authority key on both the OpenSSL and Windows
   CNG backends.
2. The `ExportableKey` and `ImportableKey` traits export and import
   `EccPrivateKey` as PKCS#8 DER on both backends. No crypto API extension is
   required to persist and reload authority private keys.
3. `azihsm_crypto::x509_builder` publicly exposes root, intermediate, and leaf
   certificate builders and their certificate templates.
4. `azihsm_ddi_tbor_types` publicly exposes `PartPolicy`, `PolicyPubKey`,
   `PolicyFlags`, and their wire serialization. A CLI crate can construct and
   parse policies directly through the workspace DDI types crate.

The existing end-to-end composition is not reusable production code. It is
private to `api/tests/src/utils/sd_provision.rs` and currently:

- wraps authority keys in the private `CaKey` test type;
- creates root, PTA, and PID leaf certificates with private helper functions;
- patches fixed-width DER templates directly;
- uses fixed test validity dates, subjects, and deterministic placeholder
  serial numbers;
- uses `expect` and `assert` instead of returning typed errors;
- builds some policies by copying bytes and patching hard-coded offsets; and
- has no authority-set manifest, persistence, loading, integrity checks, file
  permissions, or atomic-write handling.

Implementation should not make the CLI depend on `api/tests` and should not
move test provisioning helpers into the public HSM session API. Instead, the
CLI crate should contain a host-side `test_authority` module with these
fallible abstractions:

```text
TestAuthority
  generate(role)
  load(private_key_path, root_cert_path)
  save(...)
  issue_root(...)
  issue_pid_leaf(pid_public_key, ...)
  issue_pta(csr_public_key, ...)

TestAuthoritySet
  create(name)
  load(name)
  validate_manifest()
  validate_private_public_pairs()
  validate_against_policy(policy)
  issue_partition_artifacts(pid_public_key, pta_csr)
```

`TestAuthoritySet` is a CLI support type, not an HSM-owned key container. Its
private keys remain host-side test credentials. Loading must import the PKCS#8
DER key, derive its public coordinates, verify those coordinates against the
manifest and root certificate, and reject a role or curve mismatch before any
device mutation.

Certificate issuance must replace test panics with typed errors, generate
unique positive serial numbers, validate subject lengths before patching the
current fixed-width templates, and use a validity interval selected at
authority-set creation. The root certificate should be created once and
persisted with the authority set; each partition receives newly issued PID and
PTA certificates from those persisted authorities.

Policy creation must use owned `PartPolicy` and `PolicyPubKey` values from
`azihsm_ddi_tbor_types`, then serialize the complete structure. The CLI must
not duplicate field offsets from the test helper. Policy loading must verify
the exact length and parse it with `zerocopy::TryFromBytes` before comparing
POTA, SATA, optional SAPOTA, backing-partition ID, and backing-partition public
key fields.

The authority-set manifest schema is defined formally under **Manifest
schemas** (`authority-set.json`). Its `certificate_rules` fix the subject
template, the random-128-bit serial method, and the validity interval; its
`backing_policy` records the single policy created for the backing partition
and the join digest that partitions and secure domains must match. In summary,
the manifest carries at least:

- schema version and authority-set name;
- algorithm and curve;
- manufacturer, owner, SATA, POTA, and optional SAPOTA artifact paths;
- SHA-384 fingerprints of each authority public key and root certificate;
- certificate subject, serial-generation method, and validity interval; and
- the policy path and SHA-384 digest created for the backing partition.

Authority-set creation must be atomic. On Unix, authority directories use mode
`0700` and private-key files use mode `0600`. Temporary exported private-key
buffers must be zeroized after writing. The CLI must never print or include
authority private keys in evidence bundles.

The one cryptographic SDK surface that had to be added for the agreed CLI
lifecycle is unrelated to authority persistence: the public API previously could
not generate a `key_report` from a persisted masked sealing-key blob in a later
process. This was a narrow public-wrapper gap, not a missing capability, and is
now closed by the `HsmSession::sd_key_report` wrapper described below.

Unmasking already exists and is not the gap. `KeyManager::unmask_key` and
`KeyManager::unmask_key_pair` are public, and every key type restores its
device handle on use through the internal `restore_from_masked` /
`unmask_key_raw_no_res` path. `SdSealingKeyGen` creates the sealing key with
`Local` scope encoded in the masked-key envelope; after an emulator command
restores `PartLocalMK` through `part_final_ex(prev_local_mk_backup)`, firmware
selects that masking key and unmasks the blob internally. Hardware retains the
same partition-local masking key. The host never handles `PartLocalMK`.

Crucially, the sealing service never needs the host to unmask or reconstruct a
key object. The backup, restore, reseal, and peer APIs already accept the
persisted masked sealing-key bytes directly as `masked_sealing_key: &[u8]`
(`api/lib/src/session.rs`), and `key_report` attests the **masked envelope**,
not an unmasked handle. `HsmSealingKey::generate_key_report`
(`api/lib/src/algo/sealing/key.rs`) simply calls the internal primitive
`ddi::masked_key_report(session, masked_key, report_data, report)`
(`api/lib/src/ddi/sd_sealing_key_gen.rs`), which needs only the active session,
the masked bytes, and the caller report data.

The gap is that this primitive is `pub(crate)`, and its only public door,
`KeyManager::generate_key_report`, requires a live `HsmSealingKey`. That object
can only be produced by a fresh `generate_key`; its `new` constructor and
masked-key property setters are crate-private. A later CLI process therefore
holds `masked-key.bin` but has no public path to feed it to the report
primitive.

Before implementing the CLI, the SDK should expose the primitive directly as a
session-level method that accepts the masked sealing-key blob. This is
implemented as `HsmSession::sd_key_report`, named for the `sd_*` session
method family (`sd_create_remote_backup`, `sd_restore_local_backup`, …):

```rust
impl HsmSession {
    /// Attests a persisted masked sealing-key envelope via TBOR KeyReport.
    ///
    /// Uses the size-query convention: a `None` report returns the maximum
    /// report length without a device round-trip; a `Some(&mut buf)` fills the
    /// buffer and returns the actual report length. Restricted to Ver2 (CO)
    /// sessions.
    pub fn sd_key_report(
        &self,
        masked_sealing_key: &[u8],
        report_data: &[u8],
        report: Option<&mut [u8]>,
    ) -> HsmResult<usize>;
}
```

This is a thin public wrapper over the existing `ddi::masked_key_report` and is
exactly what `HsmSealingKey::generate_key_report` already does internally. It
introduces no unmasking on the host, no key reconstruction, and no exposure of
`PartLocalMK`. It is the minimal, preferred change.

A public `HsmSealingKey::from_masked(session, masked_key, pub_key_der)`
constructor plus the existing `KeyManager::generate_key_report` would also
close the gap, but it reconstructs a typed key object solely to call one method
and is heavier than necessary; the session-level wrapper is preferred.

## Flavor behavior by command

| Command | Emulator behavior | Hardware behavior |
|---|---|---|
| `create_partition` | Run the initialization flow, including `part_init_ex` and `part_final_ex` without a previous local-MK backup; generate the three test authorities and PID chains; persist the returned `local_mk_backup` and exported artifacts in the named workspace. | Initialize the hardware partition once; generate the same three test authorities and PID chains; export the public partition artifacts under the named host-side partition directory. The resulting partition state remains on the device. |
| `create_sd_sealing_key` | Reconstruct the named partition with `part_init_ex` and `part_final_ex(prev_local_mk_backup)`, then generate the sealing key. | Generate the sealing key directly on the initialized partition. |
| `key_report` | Reconstruct the named partition, restore `PartLocalMK`, reconstruct and unmask the persisted sealing-key blob inside the HSM, generate its report, and package the matching evidence bundle. | Reconstruct and unmask the persisted sealing-key blob inside the initialized partition, generate its report, and package the matching evidence bundle. |
| `create_sd` | Reconstruct the named partition, then create the security domain and write its member area plus the first remote hand-off. | Create the security domain directly on the initialized partition. |
| `restore_local_backup` | Reconstruct the named partition, then restore the security domain from the local backups. | Restore directly on the initialized partition. |
| `restore_remote_backup` | Reconstruct the named partition, then restore the security domain from the remote backup. | Restore directly on the initialized partition. |
| `reseal_remote_backup` | Reconstruct the named partition, then reseal the source remote backup. | Reseal directly on the initialized partition. |
| `create_peer_backup` | Reconstruct the named partition, then create the peer backup. | Create the peer backup directly on the initialized partition. |
| `restore_peer_backup` | Reconstruct the named partition, then restore the security domain from the peer backup. | Restore directly on the initialized partition. |
| `help` | Display CLI usage without accessing the workspace or emulator. | Display CLI usage without accessing hardware. |
| `show_partitions` | Read and correlate partition and secure-domain manifests without replaying a partition. | Read the same host-side manifests; the partition column reflects host artifacts, not live device state. |
| `show_secure_domains` | Read secure-domain manifests and hand-off lineage without replaying a partition. | Read the same host-side manifests and hand-off lineage. |

For every emulator reconstruction, the newly returned `local_mk_backup`
atomically replaces the previous file before the requested operation runs.
Hardware commands never perform this reconstruction because the initialized
partition state persists on the device.

## Partition artifact layout

```text
<working-dir>/
├── authority-sets/
│   └── <authority-set-name>/
│       ├── authority-set.json
│       ├── policy.bin
│       ├── roots/
│       │   ├── manufacturer-root.der
│       │   ├── owner-root.der
│       │   ├── sata-root.der
│       │   └── pota-root.der
│       └── secrets/
│           ├── manufacturer-private-key.der
│           ├── owner-private-key.der
│           ├── sata-private-key.der
│           └── pota-private-key.der
├── partitions/
│   └── <partition-name>/
│       ├── partition.json
│       ├── attestation/
│       │   ├── pid-public-key.der
│       │   ├── authorities/
│       │   │   ├── manufacturer-root.der
│       │   │   ├── owner-root.der
│       │   │   └── sata-root.der
│       │   ├── manufacturer-chain/
│       │   │   ├── root.der
│       │   │   └── leaf.der
│       │   ├── owner-chain/
│       │   │   ├── root.der
│       │   │   └── leaf.der
│       │   └── partition-owner-chain/
│       │       ├── root.der
│       │       └── leaf.der
│       ├── secrets/
│       │   └── co-psk.bin
│       ├── recovery/
│       │   ├── mach-seed.bin
│       │   └── part-final-local-mk-backup.bin
│       └── sealing-keys/
│           └── <key-name>/
│               ├── masked-key.bin
│               ├── public-key.der
│               └── evidence/
│                   └── <report-name>.bin
└── secure-domains/
    └── <secure-domain-name>/
        ├── secure-domain.json
        ├── policy.bin
        ├── members/
        │   ├── <backing-partition>/
        │   │   ├── member.json
        │   │   ├── pok-local-backup.bin
        │   │   └── sd-mk-backup.bin
        │   └── <joined-partition>/
        │       ├── member.json
        │       ├── pok-local-backup.bin
        │       └── sd-mk-backup.bin
        ├── remote-backups/
        │   └── <destination-partition>.bin
        └── peer-backups/
            └── <destination-partition>.bin
```

The public `attestation/`, the `secrets/` session credential, and the
sealing-key `evidence/` portions are common to both flavors: after the
default-PSK gate is cleared, every session on either flavor must present the
rotated Crypto Officer PSK in `secrets/co-psk.bin`.
The `emu` flavor additionally uses `recovery/` to compensate for the
emulator's process-local state. In the hardware flavor the partition directory
is only a host artifact catalog and is never replayed into hardware.

A partition name is the stable identifier for one logical partition's host
artifacts, and a secure-domain name is the stable identifier for one
recoverable secure domain. Each has its own directory. `partition.json` and
`secure-domain.json` are versioned manifests containing only relative paths;
the manifests record their secure-domain membership consistently. A partition
may belong to zero or one secure domain. A secure domain may contain multiple
partitions.

Partition `secrets/` contains the material needed by emulator partition
initialization. Partition `recovery/` contains the `local_mk_backup` returned
by `part_final_ex`. Partition `sealing-keys/` contains keys protected by that
partition's `PartLocalMK`. A secure-domain directory contains its policy, one
member area per partition that holds the domain, and any outstanding hand-off
backups.

### Domain artifacts: one BKS3, no generations

A secure domain is a single BKS3 (root key material), not a version history.
The CLI therefore does not keep numbered "generations"; it keeps a small set of
**role-named** artifacts, each of which is a different envelope of that one
BKS3:

- `members/<partition>/{pok-local-backup.bin,sd-mk-backup.bin}` — a partition's
  own device-local recovery point for the domain. It exists for every member
  (the backing partition and every joined partition). `restore_local_backup`
  refreshes this pair **in place** (re-masking the same BKS3 at the current
  `{svn, owner}`); a first join by `restore_remote_backup` /
  `restore_peer_backup` creates it. `member.json` records the partition's role
  and how it joined.
- `remote-backups/<destination>.bin` — an outbound hand-off: the BKS3
  HPKE-sealed to `<destination>`'s attested public key. `create_sd` writes the
  first one (for its receiver); `reseal_remote_backup` writes further ones for
  new destinations. The file is retained after the destination joins so the
  hand-off lineage remains inspectable; `member.json`/`secure-domain.json`
  record whether it has been consumed.
- `peer-backups/<destination>.bin` — the same idea for `create_peer_backup`
  hand-offs to a peer.

Because artifacts are addressed by member or destination partition, commands
never need a `--generation` selector: `restore_local_backup` uses
`members/<self>/`, `restore_remote_backup`/`restore_peer_backup` use the
hand-off addressed to `<self>`, and `reseal`/`create_peer_backup` open the
operating partition's own copy of the BKS3. The firmware's anti-rollback is
SVN-based (a backup's bound SVN must not exceed the current firmware SVN), so a
member's recovery point and every hand-off stay restorable across reboots
without any generation ordering.

The CLI writes each new or refreshed artifact through a temporary sibling file,
flushes it, and atomically renames it into place; `secure-domain.json` is
updated last through an atomic manifest replacement. In-place refreshes
(`restore_local_backup`) replace the member pair atomically, so an interrupted
write leaves the previous complete recovery point intact.

The initial CLI does not define a special recovery workflow for a hardware
`create_sd` operation that succeeds in the HSM but encounters a subsequent
host-file write failure. Normal staging and atomic-write precautions still
apply; cross-device transaction recovery is deferred.

## Manifest schemas

All four manifests are UTF-8 JSON documents with a single top-level object.
They share these conventions:

- `schema_version` is the integer literal `1`. `kind` names the manifest type.
- All path values are POSIX (`/`-separated) and resolved relative to
  `<working-dir>`; manifests never store absolute host paths.
- `*_sha384` values are 96-character lowercase-hex SHA-384 digests of the file
  or DER bytes they name.
- `pid` and `*_public_key_sha384` values are lowercase hex.
- Timestamps are RFC 3339 UTC with a `Z` suffix (for example
  `2026-09-13T18:57:00Z`).
- Every manifest is written by staging to a temporary sibling file, flushing,
  and atomically renaming over the target. Readers reject an unknown
  `schema_version`, a `kind` mismatch, a missing referenced file, or a digest
  that does not match the referenced file.

### `authority-set.json`

Located at `authority-sets/<name>/authority-set.json`. It is the canonical
record of one authority set and the single backing-partition policy derived
from it.

```json
{
  "schema_version": 1,
  "kind": "authority-set",
  "name": "prod-a",
  "created_utc": "2026-09-13T18:57:00Z",
  "algorithm": "ecdsa",
  "curve": "p384",
  "authorities": {
    "manufacturer": {
      "root_cert": "authority-sets/prod-a/roots/manufacturer-root.der",
      "private_key": "authority-sets/prod-a/secrets/manufacturer-private-key.der",
      "public_key_sha384": "…",
      "root_cert_sha384": "…"
    },
    "owner":  { "root_cert": "…", "private_key": "…", "public_key_sha384": "…", "root_cert_sha384": "…" },
    "sata":   { "root_cert": "…", "private_key": "…", "public_key_sha384": "…", "root_cert_sha384": "…" },
    "pota":   { "root_cert": "…", "private_key": "…", "public_key_sha384": "…", "root_cert_sha384": "…" },
    "sapota": null
  },
  "certificate_rules": {
    "subject_template": "CN={role} {authority_set},O=AZIHSM Sealing Service,OU=Authority",
    "serial_method": "random-128-bit",
    "validity": { "not_before": "2026-09-13T18:57:00Z", "duration_days": 3650 }
  },
  "backing_policy": { "path": "authority-sets/prod-a/policy.bin", "sha384": "…" }
}
```

- `authorities` has required `manufacturer`, `owner`, `sata`, and `pota`
  entries; `sapota` is either the same entry shape or `null` when the optional
  secondary POTA is not used.
- `certificate_rules` governs every certificate the authority set issues,
  including the partition attestation chains built during `create_partition`:
  - `subject_template` is an RFC 4514 distinguished name. `{role}` expands to
    `manufacturer`, `owner`, `sata`, `pota`, or the partition role; `{authority_set}`
    expands to `name`; `{pid}` is available for partition leaf certificates.
  - `serial_method` is `random-128-bit`: a cryptographically random, positive,
    non-zero 16-byte serial, unique per issued certificate.
  - `validity.not_before` is the issuance instant; `not_before + duration_days`
    is `notAfter`. The default `duration_days` is `3650` (ten years).
- `backing_policy` names the one policy created for this authority set from its
  SATA and POTA thumbprints. Every partition initialized under this authority
  set and every secure domain built on it MUST use this exact policy; its
  `sha384` is the join key checked by `partition.json` and `secure-domain.json`.

### `partition.json`

Located at `partitions/<name>/partition.json`. It records one logical
partition's identity, authority binding, session credential, attestation
artifacts, and named sealing keys.

```json
{
  "schema_version": 1,
  "kind": "partition",
  "name": "part-a",
  "created_utc": "2026-09-13T18:57:00Z",
  "pid": "…",
  "pid_public_key": { "path": "partitions/part-a/attestation/pid-public-key.der", "sha384": "…" },
  "authority_set": "prod-a",
  "backing_policy": { "path": "authority-sets/prod-a/policy.bin", "sha384": "…" },
  "session": { "co_psk": "partitions/part-a/secrets/co-psk.bin", "psk_rotated": true },
  "recovery": {
    "mach_seed": "partitions/part-a/recovery/mach-seed.bin",
    "part_final_local_mk_backup": "partitions/part-a/recovery/part-final-local-mk-backup.bin",
    "identity": "partitions/part-a/recovery/identity.bin"
  },
  "attestation": {
    "authorities": {
      "manufacturer_root": "partitions/part-a/attestation/authorities/manufacturer-root.der",
      "owner_root": "partitions/part-a/attestation/authorities/owner-root.der",
      "sata_root": "partitions/part-a/attestation/authorities/sata-root.der"
    },
    "manufacturer_chain":    ["partitions/part-a/attestation/manufacturer-chain/root.der",    "partitions/part-a/attestation/manufacturer-chain/leaf.der"],
    "owner_chain":           ["partitions/part-a/attestation/owner-chain/root.der",           "partitions/part-a/attestation/owner-chain/leaf.der"],
    "partition_owner_chain": ["partitions/part-a/attestation/partition-owner-chain/root.der", "partitions/part-a/attestation/partition-owner-chain/leaf.der"]
  },
  "sealing_keys": [
    {
      "name": "seal-1",
      "masked_key": "partitions/part-a/sealing-keys/seal-1/masked-key.bin",
      "public_key": "partitions/part-a/sealing-keys/seal-1/public-key.der",
      "public_key_sha384": "…",
      "reports": ["partitions/part-a/sealing-keys/seal-1/evidence/report-1.bin"]
    }
  ],
  "secure_domain": null
}
```

- `backing_policy` mirrors the authority set's `backing_policy`; the two
  `sha384` values MUST match.
- `pid` records the partition identifier observed at creation time. On the
  `emu` flavor the emulator mints a fresh PID and identity keypair on each
  allocation; to keep the identity byte-stable across the separate processes of
  the split flow, `create_partition` captures the identity and every later
  command re-injects it (see "Emulator identity injection"). A reconstructed
  emulator partition therefore reports this same PID, matching hardware.
- `session.co_psk` names the rotated Crypto Officer PSK. `psk_rotated` is
  `true` once `change_psk` has replaced the default PSK; the CLI refuses to
  operate a partition whose `psk_rotated` is `false`.
- `recovery` is present only for the `emu` flavor. On the `hw` flavor it is
  `null`, because hardware retains its partition and never replays
  `mach-seed.bin`, the `part_final_ex` local-MK backup, or the captured
  `identity.bin`.
- `sealing_keys` grows by one entry per `create_sd_sealing_key`; each entry's
  `reports` grows by one per `key_report`.
- `secure_domain` is the name of the one domain the partition belongs to, or
  `null` when it belongs to none.

### `secure-domain.json`

Located at `secure-domains/<name>/secure-domain.json`. It records domain
identity, the policy binding, the backing partition, members with their join
provenance, and outstanding hand-offs. It is the normative form of the field
list produced by `create_sd`. Because a domain is one BKS3, there is no version
or generation field.

```json
{
  "schema_version": 1,
  "kind": "secure-domain",
  "name": "sd-1",
  "created_utc": "2026-09-13T18:57:00Z",
  "authority_set": "prod-a",
  "policy": { "path": "secure-domains/sd-1/policy.bin", "sha384": "…" },
  "backing_partition": { "name": "part-a", "pid": "…" },
  "backup_scope": "cross-partition",
  "members": [
    {
      "partition": "part-a",
      "pid": "…",
      "role": "backing",
      "joined_via": "create_sd",
      "source_partition": null,
      "created_utc": "2026-09-13T18:57:00Z"
    }
  ],
  "handoffs": [
    {
      "kind": "remote",
      "destination": "part-b",
      "pid": "…",
      "sealing_key_sha384": "…",
      "evidence_ref": "part-b/seal-b/report-b",
      "evidence_sha384": "…",
      "artifact": "secure-domains/sd-1/remote-backups/part-b.bin",
      "created_by": "create_sd",
      "source_partition": "part-a",
      "consumed": false
    }
  ]
}
```

- `policy.sha384` MUST equal the authority set's `backing_policy.sha384` and the
  backing partition's `backing_policy.sha384`; `secure-domains/<name>/policy.bin`
  is a byte-identical copy of the authority-set policy.
- `backing_partition` is the single partition named by the policy's
  `backup_part_id` and is the only partition that could have run `create_sd`.
- `backup_scope` is `self` or `cross-partition`. For `self`, the sole hand-off
  destination equals `backing_partition.name` and `members` contains that
  partition once with no outstanding hand-off.
- `members` lists every partition that currently holds the domain's BKS3, each
  with a `members/<partition>/member.json` counterpart. `role` is `backing`
  (this partition is `backup_part_id`, joined via `create_sd`) or `member`
  (joined later via a restore). `joined_via` is the command that installed the
  BKS3 locally; `source_partition` names the partition whose hand-off it
  consumed (`null` for the backing partition).
- `handoffs` lists every outbound backup addressed to a destination that has not
  necessarily joined yet. `kind` is `remote` or `peer`; `created_by` is
  `create_sd`, `reseal_remote_backup`, or `create_peer_backup`;
  `source_partition` is the member that produced it; `consumed` flips to `true`
  when the destination runs the matching restore and appears in `members`.
  Hand-off files are retained after consumption so lineage stays inspectable.

### `member.json`

Located at `secure-domains/<name>/members/<partition>/member.json`. It is the
self-describing record for one partition's copy of the domain's BKS3.

```json
{
  "schema_version": 1,
  "kind": "member",
  "partition": "part-b",
  "pid": "…",
  "role": "member",
  "joined_via": "restore_remote_backup",
  "source_partition": "part-a",
  "source_handoff": "secure-domains/sd-1/remote-backups/part-b.bin",
  "created_utc": "2026-09-13T19:04:00Z",
  "updated_utc": "2026-09-13T19:20:00Z",
  "artifacts": [
    { "name": "pok-local-backup.bin", "length": 992, "sha384": "…" },
    { "name": "sd-mk-backup.bin",     "length": 164, "sha384": "…" }
  ]
}
```

- `role` and `joined_via` match this partition's entry in `secure-domain.json`.
  For the backing partition `role` is `backing`, `joined_via` is `create_sd`,
  and `source_partition`/`source_handoff` are `null`.
- `created_utc` is when the member area was first written (the join);
  `updated_utc` is refreshed every time `restore_local_backup` re-masks the
  BKS3 in place. Both `artifacts` digests are updated on that in-place refresh.
- `artifacts` lists the two device-local recovery files with byte `length` and
  `sha384`. Readers rely on this list rather than a fixed filename set.

## Emulator partition creation

`create_partition` initializes the transient emulator partition and creates its
named workspace. It runs the security-domain provisioning flow — bootstrap the
Crypto Officer (CO) session under the partition default PSK, rotate that PSK
with `change_psk`, reopen under the rotated PSK, `part_init_ex`, build the
POTA-anchored PTA chain from the returned CSR, then `part_final_ex` — to reach
the `Initialized` state. It persists:

1. The rotated CO PSK used to clear the default-PSK gate
   (`secrets/co-psk.bin`).
2. The machine seed supplied to `part_init_ex` (`recovery/mach-seed.bin`), a
   fixed input every later reconstruction replays.
3. A reference to the named authority set whose POTA endorsed the partition
   identity and whose SATA issued its partition-owner evidence chain.
4. The `local_mk_backup` returned by `part_final_ex`
   (`recovery/part-final-local-mk-backup.bin`).
5. The captured partition identity — PID, identity public key, and identity
   private scalar — for re-injection on later reconstructions
   (`recovery/identity.bin`). Emulator-only; see "Emulator identity injection".

The security-domain session is authenticated only by the PSK handshake; there
is no application id, application PIN, partition BMK, or owner backup key
(OBK/MOBK) in this flow. Those belong to the legacy `establish_credential` /
`init_bk3` provisioning path, which the sealing service does not use.

## Emulator operation lifecycle

There is no user-facing `partition recover` command. Every later command that
needs the emulator partition's local masking key performs reconstruction as an
internal prerequisite:

1. Load and validate
   `<working-dir>/partitions/<partition>/partition.json`.
2. Reset the emulator partition to factory state.
3. Run the complete V2 TBOR session setup: `open_session_ex`
   (`OpenSessionInit` / `OpenSessionFinish`) under the partition default CO
   PSK, `change_psk` to the stored `secrets/co-psk.bin`, close the bootstrap
   session, then reopen `open_session_ex` under the rotated CO PSK.
4. Run `part_init_ex`, supplying `recovery/mach-seed.bin` and the partition
   policy, then build the POTA-anchored PTA chain by signing the returned CSR
   with the authority set's POTA private key.
5. Run `part_final_ex`, supplying
   `recovery/part-final-local-mk-backup.bin` as the previous
   `local_mk_backup`. Persist the newly returned value atomically.
6. Re-inject the captured partition identity from `recovery/identity.bin`
   (PID, identity public key, and identity private scalar) so the
   reconstructed partition carries the exact identity recorded at creation.
7. Execute the requested secure-domain operation, such as sealing-key
   generation.
8. Close the session and exit.

Reconstruction reproduces two independent kinds of state. The local masking key
is PID-independent: `part_final_ex(prev_local_mk)` restores the original
`PartLocalMK` into whatever fresh partition exists, and the masked sealing-key
blob is bound to the platform identity `{svn, owner}` — its anti-rollback
anchor — not to the PID, so masking and unmasking survive a changed PID on their
own. The partition identity, by contrast, IS load-bearing for attestation and
backup: `key_report` signs its report with the partition identity key and binds
`policy_hash`, and `create_sd` requires the live PID and identity public key to
equal the policy's `backup_part_id` / `backup_part_pub_key`. Because the
emulator mints a random identity per process, the split flow would otherwise
present an internally inconsistent evidence bundle across its separate command
invocations. The emulator therefore captures the identity once at creation and
re-injects it on every reconstruction (see "Emulator identity injection"),
making the identity byte-stable exactly as it is on hardware.

The values fixed across reboots are `mach_seed`, the POTA private key, the
policy, and — on the emulator — the captured partition identity. The
POTA-anchored PTA chain is a regenerated intermediate, not a persisted fixed
input: step 4 rebuilds an equivalent chain each time by signing the CSR that
`part_init_ex` returns with the persisted POTA private key. Re-signing may vary
the ECDSA signature, certificate serial, and validity dates, which the HSM does
not require to be byte-identical — it validates the chain against the POTA
anchor in the policy and the PTA public key.

The `part_final_ex` local-MK backup is security-domain reconstruction state.
It is not a partition session credential and it is not an SD local-restore
backup.

## Emulator identity injection

The identity injection mechanism keeps a partition's identity byte-stable across
the separate CLI processes of the split flow, so that on the emulator the
sequence `create_partition` → `create_sd_sealing_key` → `key_report` →
`create_sd` (each its own process) behaves exactly as it does across separate
hardware VMs. It is **emulator-only** and has **no effect on the hardware path**.
The firmware and DDI layers live in crates that are only ever built for the
emulator (`fw/plat/std/*`, `ddi/emu`), so they need no feature gate of their own;
the CLI compiles its use of them behind its existing `emu` Cargo feature, so
nothing here is ever compiled into a hardware build.

### Why it is needed

On the emulator the partition identity is minted with a non-seedable RNG at
`part_alloc`, and the identity keypair is re-minted at every `part.reset()`
(`erase` = `part_disable` + `part_enable`). Each CLI process therefore starts
from a different identity. That breaks attestation and backup, which are
identity-bound: `key_report` signs its report with the partition identity key,
and `create_sd` checks the live PID and identity public key against the policy's
`backup_part_id` / `backup_part_pub_key`. Without a stable identity the evidence
produced by one process cannot be verified against the policy or chains anchored
in another. Hardware does not have this problem because a real partition retains
its identity across reboots.

### Identity state

Three fields constitute the partition identity:

| Field | Firmware location | Size |
|-------|-------------------|------|
| PID | `entry.id` | 16 bytes |
| identity public key (raw `X ‖ Y`, big-endian) | `entry.id_pub_key` | 96 bytes |
| identity private key (bare P-384 scalar) | vault slot `entry.id_key_id` | 48 bytes |

All three are captured at creation and persisted to
`partitions/<name>/recovery/identity.bin` (160 bytes total). The file is written
only on the `emu` flavor, lives under the generated (git-ignored) workspace, and
is never produced on hardware.

### Capture and replay points

- **Capture** happens at the end of `create_partition`, after the provisioning
  reset, so the captured bytes match the `pid` / `pid_public_key` the run
  already records.
- **Re-injection** happens as the final step of every later command's
  reconstruction — after `part_final_ex`, once the last identity regeneration
  has occurred — and before the requested secure-domain operation runs. The
  injected identity overwrites the three fields so firmware `pid()`,
  `ex_pub_key()`, and the identity vault key all return the captured values, and
  the leaf-certificate cache is invalidated so any certificate chain is rebuilt
  over the injected public key.

### Mechanism

The emulator runs a single process-global `StdHsm`, and all partition-lifecycle
operations ride an IPC channel to its Embassy thread. Injection reuses that same
path rather than the DDI wire, so it needs no changes to the api or DDI request
contract:

1. **PAL** (`fw/plat/std/pal/src/part.rs`) — two internal methods in the
   emulator-only PAL crate: one exports `{PID, identity public key, identity
   private scalar}` from the partition entry and its vault; the other overwrites
   `entry.id` and `entry.id_pub_key`, replaces the identity vault key from the
   supplied scalar, updates `entry.id_key_id`, and clears the leaf-cert cache.
2. **IPC command + `StdHsm`** (`fw/plat/std/lib/src/lib.rs`) — two new
   `PartCommand` variants and matching public `StdHsm` methods
   (`part_export_identity` / `part_inject_identity`), mirroring `part_alloc` /
   `part_enable`.
3. **Emulator DDI side channel** (`ddi/emu/src/ddi.rs`) — two free functions
   that reach the process-global `StdHsm` and drive the export/inject methods
   for the fixed emulator PID. These are the CLI's entry points.
4. **CLI** (`api/tools/sealing-service`) — under the `emu` feature only,
   `create_partition` calls the export function and persists `identity.bin`;
   `open_operating_session` loads it and calls the inject function as the final
   reconstruction step. The `hw` build compiles none of this.

### Guardrails

- The firmware and DDI layers live in emulator-only crates (`fw/plat/std/*`,
  `ddi/emu`) and the CLI compiles its use of them behind its existing `emu`
  feature, so the mechanism is never compiled into a hardware build; it uses no
  `unsafe` code.
- The exported private scalar is held in zeroizing memory in process and
  persisted in plaintext only under the git-ignored emulator workspace — an
  accepted property of emulator test scaffolding, and never present on hardware.
- Injection is applied after the last identity regeneration in the
  reconstruction, guaranteeing the value the requested operation observes is the
  captured identity.

## Hardware operation lifecycle

`create_partition` provisions the hardware partition once. The initialized
partition and its local masking key remain on the device. For every later
hardware command:

1. Open the required CO session through the compiled hardware DDI path with
   `open_session_ex`, presenting the rotated CO PSK from `secrets/co-psk.bin`.
2. Execute the requested secure-domain operation directly.
3. Write the requested output artifact, if any.
4. Close the session and exit.

The later hardware commands must not call partition reset, `change_psk`,
`part_init_ex`, or `part_final_ex`. They also must not consume an emulator
workspace's `mach_seed`, `local_mk_backup`, or other recovery files.

## Named sealing keys

On the emulator, `create_sd_sealing_key --partition <name> --sealing-key <key-name>`
creates a stable key directory under `artifacts/sealing-keys/`. Later commands
identify the key by that name:

```text
key_report --partition <name> --sealing-key <key-name> --report <report-name>
```

Both partition names and key names use the same restricted single-component
identifier format. Existing key directories are never overwritten.

`key_report` must perform the complete key-recovery sequence within its
one-shot invocation:

**`emu`-flavor preparation:** reconstruct the named partition with
`part_init_ex` followed by `part_final_ex(prev_local_mk_backup)`, restoring its
`PartLocalMK`. This code is gated by `#[cfg(feature = "emu")]` and is absent
from the `hw` flavor.

**Common flow after backend preparation:**

1. Load the named key's persisted masked sealing-key blob and public key.
2. Call `session.sd_key_report(masked_key, report_data, report)`, passing
   `report_data` (a caller-supplied 128-byte file or the all-zero default). The
   two-call size-query convention returns the maximum length for a `None`
   report and fills the buffer for a `Some` report. The HSM selects
   `PartLocalMK` from the blob's `Local` scope and unmasks internally; the host
   performs no reconstruction or unmasking.
3. Load the partition's three DER certificate chains, verify each chain's leaf
   certifies the partition PID public key, and package the chains together with
   the returned COSE_Sign1 report into the sealing key's `.bin` evidence bundle.

The plaintext sealing key and `PartLocalMK` never leave the HSM.

## Hardware artifact output

The `hw` flavor writes host-visible results, including the generated test
certificate chains, masked sealing keys, public keys, evidence bundles, and
backup blobs, beneath the selected partition artifact directory in
`--working-dir`.
Commands may use the partition name to resolve those artifacts.

The hardware partition directory remains an artifact destination, not a
replayable partition workspace. Its folder or file names do not select,
restore, or recreate hardware partition state.

## Help and workspace inventory

`help` displays all supported commands and their invocation syntax:

```text
azihsm-sealing-service help
azihsm-sealing-service help <command>
```

The standard `--help` forms provide the same information:

```text
azihsm-sealing-service --help
azihsm-sealing-service <command> --help
```

The two inventory commands are read-only workspace commands available in both
flavors. Neither takes arguments; each always lists every entry in the
workspace:

```text
azihsm-sealing-service --working-dir <path> show_partitions
azihsm-sealing-service --working-dir <path> show_secure_domains
```

`show_partitions` scans the versioned manifests beneath `partitions/` and
correlates each partition with the secure domain it belongs to, printing a
deterministically sorted per-partition table. The `SD ROLE` column is `backing`
or `member` when the partition holds a domain, and `-` otherwise:

```text
PARTITION    AUTHORITY SET  SEALING KEYS        SECURE DOMAIN    SD ROLE
partition_1  prod-a         key_1, key_2, key_3 secure_domain_1  backing
partition_2  prod-a         key_4               secure_domain_1  member
partition_3  prod-a         -                   -                -
```

`show_secure_domains` scans `secure-domains/` and renders, per domain, the
backing partition, the members with their join provenance, and the outstanding
and consumed hand-offs — so the reader can see which partition is the root of
the domain and how every other member joined:

```text
SECURE DOMAIN  secure_domain_1   (policy ab12…, backing partition_1)
  members
    partition_1  backing  create_sd                          (root)
    partition_2  member   restore_remote  <- partition_1
  hand-offs
    remote  partition_2  create_sd          from partition_1  consumed
    remote  partition_3  reseal             from partition_1  outstanding
    peer    partition_4  create_peer        from partition_1  outstanding
```

Both commands read metadata and artifact names only. They do not replay a
partition, open an HSM session, read secret-file contents, decode backup blobs,
or modify the workspace. A missing or invalid manifest is reported as an
inventory error rather than silently omitted.

## Safety requirements

- Emulator partition and secure-domain names are single validated path
  components.
- Existing partition workspaces are never overwritten.
- Existing secure-domain workspaces are never overwritten.
- Hand-off backups (`remote-backups/`, `peer-backups/`) are write-once per
  destination and are never modified after creation; a member's device-local
  recovery pair is refreshed only by `restore_local_backup`, atomically in
  place.
- A new workspace is assembled under a temporary sibling directory and
  atomically renamed into place only after provisioning succeeds.
- Every new or refreshed backup artifact is written through a temporary sibling
  file and atomically renamed; `secure-domain.json` is updated last, so readers
  continue using the previous complete artifact set after an interrupted write.
- On Unix, partition directories and their subdirectories use mode `0700`;
  secret files use mode `0600`.
- Private keys, masking-key recovery material, and their contents must never
  be printed.
- An emulator-wide lock is required because all logical partitions share one
  transient emulator instance.
- A partition-level workspace lock is required before an emulator command
  reconstructs or mutates a logical partition.
- Non-initialization hardware commands must never perform an implicit partition
  reset or provisioning operation.

## Flavor invariants

- Emulator workspaces represent recoverable logical partitions, not
  simultaneously resident hardware partitions.
- Every emulator command that needs partition-local state is one-shot:
  reconstruct with the saved `local_mk_backup`, then execute the requested API.
- Every hardware command after `create_partition` assumes its target partition is
  still initialized on the device and calls the requested API directly.
- Emulator recovery state and hardware partition state are separate concepts
  and must not share an initialization path.
- Partition replay is compiled only into the `emu` flavor. It is not selected
  by a runtime flag and cannot execute in the `hw` flavor.

## Shared backing-partition policy model

All partitions in a secure domain — the backing partition that creates it (A)
and every receiver or peer that later joins (B, C, …) — initialize under the
**one** authority-set policy (`authority-sets/<name>/policy.bin`). That policy
names A as the backing partition: `backup_part_id` is A's PID and
`backup_part_pub_key` is A's PID public key. Because the PID is deterministically
derived from `mach_seed`, A's PID is known before any partition initializes, so
the policy can carry it up front.

A receiver's own PID differs from `backup_part_id`, and this is correct and
supported. The firmware enforces the backing-partition identity **per
operation**, not at initialization:

- `part_init_ex` treats `backup_part_id` (and `backup_part_pub_key` beyond a
  well-formed-key check) as opaque and does not compare it to the initializing
  partition's PID (`fw/core/lib/src/ddi/tbor/policy.rs`). B and C initialize
  cleanly under the identical policy bytes.
- Creating the remote backup requires the caller's PID to equal
  `backup_part_id` (`fw/core/lib/src/ddi/tbor/sd_create_remote_backup.rs`), so
  only A can mint the security-domain backup.
- The restore, reseal, and peer handlers do not reference `backup_part_id` at
  all, so B and C restore and join with no init-time or restore-time identity
  equality constraint.

This confirms the single-`policy.bin`-per-authority-set layout and the single
policy `sha384` join key shared by the authority set, every partition, and the
secure domain. A true multi-partition integration test — A creates the domain,
B and C are initialized independently and then restore — remains a required
acceptance gate that exercises the non-self `backup_part_id` path end to end.

## Open design decisions

The design has no remaining blocking decisions. The former open question of
whether a single backing-partition policy is accepted by `part_init_ex` for
independently initialized receivers is resolved above under **Shared
backing-partition policy model**; it is validated by the required
multi-partition integration test rather than left as a design unknown.

## Testing

The tool has two tiers of automated tests.

**Unit tests** live beside the code they cover — for example the evidence
bundle encode/decode round-trip and its rejection cases in
`src/evidence.rs`. They run under either flavor with `cargo test -p
azihsm_sealing_service`.

**End-to-end integration tests** live in `tests/e2e.rs`. Each test spawns the
built `azihsm-sealing-service` binary once per command — a distinct OS process
per step, exchanging file-based state through a shared, disposable
`--working-dir` — so they exercise the real cross-process split flow rather than
in-process helpers. The whole file is gated on `#[cfg(feature = "emu")]`:
only the emulator flavor runs without physical HSM hardware, and the
emulator identity-injection layer keeps the partition identity byte-stable
across processes so the split flow behaves like hardware. Built without
`--features emu`, the file compiles to an empty test crate.

Coverage:

- `full_remote_backup_round_trip` — two partitions on a shared authority set,
  sealing keys and key reports on both, `create_sd` on the backing partition
  addressed to the receiver, then `restore_remote_backup` on the receiver.
  Asserts the receiver's member area, the domain membership and consumed
  hand-off, the receiver's recorded membership, and that a second restore is
  rejected.
- `self_backup_single_partition` — a self-backup domain has a single backing
  member and an immediately-consumed hand-off, and a backing partition already
  in a domain cannot back another.
- `restore_without_domain_is_rejected` — restoring into a non-existent domain
  fails without mutating the receiver's state.
- `restore_local_backup_refreshes_recovery_pair` — a member refreshes its own
  device-local recovery pair in place; the member manifest and its on-disk
  artifacts stay consistent (a second refresh re-reads and re-verifies them),
  and a non-member partition cannot self-restore.
- `reseal_forwards_domain_to_third_partition` — the full A → B → C forwarding
  chain: A creates the domain for B, B joins, B reseals the same BKS3 to a new
  destination C, and C consumes the reseal hand-off via its own
  `restore_remote_backup`. Asserts the outstanding hand-off is sourced by B, C
  joins as a third member with lineage back to B, a partition with no inbound
  backup cannot reseal, and resealing to an existing member is rejected.
- `peer_backup_admits_new_member` — the peer-backup pair: member B hands the
  domain's BKS3 to peer C (sealed to C's attested key) via `create_peer_backup`,
  and C joins by consuming that peer hand-off via `restore_peer_backup`. Asserts
  the outstanding `peer`-kind hand-off is sourced by B, C joins with peer lineage
  back to B, a non-member cannot create a peer backup, and a second peer restore
  is rejected.
- `show_partitions_lists_domain_membership` — the read-only partition inventory:
  A backs a domain that B joins while C stays unaffiliated. Asserts the table is
  headed and sorted, that A shows its authority set, domain, and `backing` role,
  that B shows the domain and `member` role, and that the non-member C ends in
  the `-` domain and role columns.
- `show_secure_domains_renders_lineage` — the read-only domain inventory: A backs
  a domain, B joins, then B reseals to a not-yet-joined C. Asserts the domain
  header names the backing partition, the backing member is the `(root)` while B
  shows `<- part-a` provenance, B's join is a `consumed` hand-off, and the
  outstanding reseal to C is rendered as `outstanding`.

Run the full suite with:

```bash
cargo test -p azihsm_sealing_service --features emu
```

