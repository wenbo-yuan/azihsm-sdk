# Sealing Service CLI

`azihsm-sealing-service` is a command-line tool that drives the sealing-service
secure-domain provisioning, backup, and recovery flow. Each command is a
**separate OS process** that exchanges state through a single **binary state
file** — a self-contained container that holds the entire workspace — selected
by the `AZIHSM_SEALING_STATE_PATH` environment variable. This deliberately
mirrors the multi-VM reality on hardware: on a real deployment each partition
lives on its own machine, so the tool never keeps a partition "live" in memory
across commands.

Each command transparently unpacks the state file into a private scratch
directory, runs, then repacks it and writes it back atomically (owner-only,
`0600`). If a command fails, the state file is left untouched, so every command
is all-or-nothing. When the env var is unset (or empty), the tool defaults to
`./azihsm-sealing-state.bin` in the current directory; a missing file is treated
as an empty workspace and created on first write.

The full design contract lives in
[`api/docs/design-sealing-service-cli.md`](../../docs/design-sealing-service-cli.md);
this README is the operator's quick reference plus a walkthrough of the
end-to-end test flows.

## Flavors

One binary, two compile-time flavors selected by a Cargo feature:

| Flavor | Build | Backend | Partition state |
|--------|-------|---------|-----------------|
| `hw` (default) | `cargo build -p azihsm_sealing_service` | Platform DDI | Hardware keeps the initialized partition alive across processes |
| `emu` | `cargo build -p azihsm_sealing_service --features emu` | In-process emulator firmware | No partition survives the process; each command reconstructs partition state from persisted `recovery/` artifacts before calling its API |

Both flavors expose the identical CLI surface. The flavor is fixed at build time
and reported by `azihsm-sealing-service --version`; there is no runtime backend
switch.

## State file

All host-side state lives in one binary container file. Point every command at
the same file with the `AZIHSM_SEALING_STATE_PATH` environment variable:

```bash
export AZIHSM_SEALING_STATE_PATH=/tmp/sealing-demo.bin
```

- **Unset or empty** → defaults to `./azihsm-sealing-state.bin`.
- **Missing file** → treated as an empty workspace; created on the first command
  that writes state.
- **Permissions** → written owner-only (`0600`), since it holds sealing secrets.

There is no `--working-dir` option: the container replaces the on-disk directory
tree. The logical layout *inside* the container is unchanged (see
[Workspace layout](#workspace-layout)).

## Commands

Evidence arguments (`--receiver-evidence`, `--sender-evidence`,
`--peer-evidence`) are `<partition>/<key>/<report>` **workspace references**, not
filesystem paths — they address entries inside the state container.

| Command | Purpose | Key inputs (read) | Outputs (written) |
|---------|---------|-------------------|-------------------|
| `create_partition` | Initialize a partition workspace and its attestation artifacts | authority set / policy | `partitions/<p>/` (`attestation/`, `secrets/co-psk.bin`, `recovery/`); new-authority mode also writes `authority-sets/<a>/` + `policy.bin` |
| `create_sd_sealing_key` | Generate a named SD sealing key on a partition | partition manifest | `sealing-keys/<key>/{masked-key,public-key}` |
| `key_report` | Produce an attestation evidence bundle for a sealing key | sealing key | `sealing-keys/<key>/evidence/<report>.bin` |
| `create_remote_backup` | Create a secure domain and its first backups (backing partition only) | backing sealing key, receiver evidence | `secure-domains/<d>/` with `members/<backing>/{pok-local-backup,sd-mk-backup}.bin` + `remote-backups/<receiver>.bin` |
| `restore_local_backup` | Refresh the operating partition's own device-local recovery point | member's own recovery pair | `members/<p>/{pok-local-backup,sd-mk-backup}.bin` (in place) |
| `restore_remote_backup` | Join a domain from a remote hand-off addressed to this partition | receiver sealing key, sender evidence, `remote-backups/<receiver>.bin` | `members/<receiver>/…`; consumes the inbound hand-off |
| `reseal_remote_backup` | Re-wrap a domain's BKS3 to a new destination partition | source sealing key, source + receiver evidence | new hand-off `remote-backups/<new-dest>.bin` |
| `create_peer_backup` | Produce a peer hand-off for another partition in the domain | sender sealing key, peer evidence | new hand-off `peer-backups/<dest>.bin` |
| `restore_peer_backup` | Join a domain from a peer hand-off addressed to this partition | receiver sealing key, peer evidence, `peer-backups/<receiver>.bin` | `members/<receiver>/…`; consumes the inbound hand-off |
| `show_partitions` | Print a per-partition inventory table (sealing keys with their key reports) | all partition + domain manifests | stdout only |
| `show_secure_domains` | Print per-domain membership and hand-off lineage | all domain manifests | stdout only |
| `help` | Print usage for the tool or one command | — | stdout only |

### Help

`clap` provides every help form:

```text
azihsm-sealing-service help              # list all commands
azihsm-sealing-service help <command>    # usage for one command
azihsm-sealing-service --help            # same as `help`
azihsm-sealing-service <command> --help  # usage for one command
```

## Quickstart

A minimal single-partition (self-backup) flow on the emulator. Every line is a
separate process; all share one state file via the environment variable:

```bash
BIN=target/debug/azihsm-sealing-service
export AZIHSM_SEALING_STATE_PATH=/tmp/sealing-demo.bin

# 1. Provision a partition with a fresh authority set.
$BIN create_partition --partition p1 --new-authority-set auth-a

# 2. Mint a sealing key and attest it (produces an evidence bundle).
$BIN create_sd_sealing_key --partition p1 --sealing-key k1
$BIN key_report --partition p1 --sealing-key k1 --report r1

# 3. Create a secure domain backed by p1, addressed to itself (self-backup).
$BIN create_remote_backup \
    --partition p1 --secure-domain sd1 --sealing-key k1 --receiver-evidence p1/k1/r1

# 4. Inspect the workspace.
$BIN show_partitions
$BIN show_secure_domains
```

To admit a *second* partition, provision it against the **same** authority set
(its single stored policy is loaded from the state container automatically), then
run `create_remote_backup` on the backing partition addressed to the new partition's
evidence, and `restore_remote_backup` on the new partition:

```bash
$BIN create_partition --partition p2 --authority-set auth-a
$BIN create_sd_sealing_key --partition p2 --sealing-key k2
$BIN key_report --partition p2 --sealing-key k2 --report r2

# Backing p1 hands off to p2; p2 joins.
$BIN create_remote_backup \
    --partition p1 --secure-domain sd1 --sealing-key k1 --receiver-evidence p2/k2/r2
$BIN restore_remote_backup \
    --partition p2 --secure-domain sd1 --sealing-key k2 --sender-evidence p1/k1/r1
```

Each authority set owns exactly one shared policy (derived from the backing
partition when the set is created), so reusing an authority set is all that is
needed — there is no separate policy argument.

## Workspace layout

The state container is a single binary file (`AZIHSM_SEALING_STATE_PATH`). Its
logical contents — what each command reads and writes — form this tree:

```text
<state container>
├── authority-sets/<name>/   authority-set.json, policy.bin, roots/, secrets/
├── partitions/<name>/       partition.json, attestation/, secrets/, recovery/, sealing-keys/
└── secure-domains/<name>/   secure-domain.json, policy.bin,
                             members/<partition>/{member.json,pok-local-backup.bin,sd-mk-backup.bin},
                             remote-backups/<dest>.bin, peer-backups/<dest>.bin
```

A partition belongs to zero or one secure domain; a domain may span many
partitions. `remote-backups/` and `peer-backups/` hold **outstanding**
hand-offs — an entry is deleted (consumed) once the destination joins.

## Testing

Tests are split into two layers, both in the `azihsm_sealing_service` package:

- **Unit tests** (`#[cfg(test)]`) — the evidence-bundle codec (`src/evidence.rs`)
  and the state-container format (`src/container.rs`, covering pack/unpack
  round-trips, truncation, and path-escape rejection). They run in every flavor.
- **End-to-end tests** (`tests/e2e.rs`, gated `#![cfg(feature = "emu")]`) — 8
  tests that spawn the *built binary* once per command, each pointed at a
  disposable state file via `AZIHSM_SEALING_STATE_PATH`, exercising the real
  cross-process split flow. They decode the resulting `.bin` container in-process
  to assert on the persisted manifests and artifacts. They run only on the `emu`
  flavor, because the emulator's identity injection makes the partition identity
  byte-stable across the separate command processes (mock and hardware flavors
  cannot reproduce the split flow deterministically).

Run everything on the emulator flavor:

```bash
cargo test -p azihsm_sealing_service --features emu
```

### Precheck integration

`cargo xtask precheck` (the minimal default) builds the `mock` flavor and so runs
only the unit tests (evidence + container); the emu-gated e2e suite is compiled
out. The full run executes the e2e suite via the dedicated `ci-emu-sealing`
nextest profile:

```bash
cargo xtask precheck --full     # includes the emu e2e suite
# or, on demand:
cargo xtask precheck --nextest -F emu -p azihsm_sealing_service
```

### End-to-end test flows

Each e2e test builds only the partitions it needs, drives the split flow, and
then decodes the persisted state container to read the manifests and artifacts
back and assert the outcome. "Reads back" below means assertions on stdout
and/or on the JSON manifests inside the container.

#### `full_remote_backup_round_trip` — 2 partitions
- **Partitions:** `part-a` (backing) and `part-b` (receiver) on a shared
  authority set.
- **Writes:** provisions both partitions (sealing keys + key reports); `part-a`
  runs `create_remote_backup` (domain `sd-x`, `members/part-a/…`, outstanding
  `remote-backups/part-b.bin`); `part-b` runs `restore_remote_backup`, writing
  `members/part-b/{pok-local-backup,sd-mk-backup}.bin` and consuming the hand-off.
- **Reads back:** `create_remote_backup` reports a cross-partition scope; before the
  restore the hand-off exists and `part-b` is not yet a member; after it, the
  join summary prints, `part-b`'s member artifacts exist, and `member.json`
  records `role=member`, `joined_via=restore_remote_backup`,
  `source_partition=part-a`. The domain manifest lists both partitions (a
  backing, b member) with the single hand-off marked consumed, and `part-b`'s
  `partition.json` records `secure_domain=sd-x`. Re-running the restore is
  rejected (already a member).

#### `self_backup_single_partition` — 1 partition
- **Partitions:** `solo`, which names *itself* as receiver.
- **Writes:** provisions `solo`; `create_remote_backup` with `--receiver-evidence solo/sk/rep`
  creates domain `sd-solo` with `backup_scope=self`.
- **Reads back:** `create_remote_backup` reports the `(self)` scope; the domain manifest has
  a single backing member and a hand-off that is consumed on creation. A backing
  partition already in a domain cannot back a second one (rejected).

#### `restore_without_domain_is_rejected` — 2 partitions
- **Partitions:** `part-a` and `part-b`, provisioned but with **no** `create_remote_backup`.
- **Writes:** provisioning only; a `restore_remote_backup` against the
  nonexistent domain `ghost` must fail without mutating state.
- **Reads back:** no member area is created, and `part-b`'s `partition.json`
  still records no domain — confirming a failed restore does not partially
  mutate the workspace.

#### `restore_local_backup_refreshes_recovery_pair` — 1 member + 1 non-member
- **Partitions:** `solo` (a self-backup member) and `loner` (belongs to no
  domain).
- **Writes:** provisions `solo`, creates `sd-solo`; `restore_local_backup`
  refreshes `members/solo/{pok-local-backup,sd-mk-backup}.bin` in place; runs a
  second refresh; provisions `loner`.
- **Reads back:** the refresh summary prints; the member manifest's recorded
  artifact lengths match the files in the container (no drift); a second refresh
  succeeds by re-reading and re-verifying the freshly written pair; `loner`
  cannot self-restore (rejected — not a member of any domain).

#### `reseal_forwards_domain_to_third_partition` — 3 partitions
- **Partitions:** `part-a` (backing) → `part-b` (member) → `part-c` (new
  destination); the full A → B → C forwarding chain.
- **Writes:** `part-a` creates `sd-x` for `part-b`; `part-b` joins; `part-b`
  runs `reseal_remote_backup` to `part-c`, writing an outstanding
  `remote-backups/part-c.bin`; `part-c` consumes it via `restore_remote_backup`.
- **Reads back:** a partition with no inbound backup (`part-a`) cannot reseal
  (rejected); `part-b`'s reseal reports success; the new hand-off is outstanding,
  sourced by `part-b`, and `created_by=reseal_remote_backup`. After `part-c`
  restores, the domain has three members and `part-c`'s lineage points back to
  `part-b`; resealing again to an existing member is rejected.

#### `reseal_relays_without_joining` — 3 partitions
- **Partitions:** `part-a` (backing) → `part-b` (relay, never joins) → `part-c`
  (new destination).
- **Writes:** `part-a` creates `sd-x` addressed to `part-b`; `part-b` reseals
  straight to `part-c` **without** running `restore_remote_backup`, writing an
  outstanding `remote-backups/part-c.bin`; `part-c` consumes it.
- **Reads back:** the reseal succeeds even though `part-b` never joined
  (matching the firmware, which needs only the inbound `pok_remote_backup`);
  `part-b` is not added as a member and has no member area; after `part-c`
  restores, the domain has exactly `part-a` and `part-c` as members and
  `part-c`'s lineage points back to `part-b`.

#### `peer_backup_admits_new_member` — 3 partitions
- **Partitions:** `part-a` (backing), `part-b` (member), `part-c` (peer joiner).
- **Writes:** `part-a` creates `sd-x` for `part-b`; `part-b` joins; `part-b`
  runs `create_peer_backup` for `part-c`, writing an outstanding
  `peer-backups/part-c.bin`; `part-c` joins via `restore_peer_backup`.
- **Reads back:** a non-member (`part-c`) cannot create a peer backup (rejected);
  the peer-backup summary prints; the hand-off is `kind=peer`, outstanding,
  sourced by `part-b`, `created_by=create_peer_backup`. After the restore,
  `part-c` is a member with `joined_via=restore_peer_backup`,
  `source_partition=part-b`, its recovery pair is materialized, the hand-off is
  consumed, and `part-c`'s `partition.json` records the domain. A second peer
  restore is rejected.

#### `show_partitions_lists_domain_membership` — 3 partitions (read-only)
- **Partitions:** `part-a` (backing of `sd-x`), `part-b` (member), `part-c`
  (unaffiliated).
- **Writes:** provisioning + one domain; `show_partitions` itself writes nothing.
- **Reads back:** the stdout table is headed and sorted (`part-a` < `part-b` <
  `part-c`); `part-a`'s row shows its authority set, `sd-x`, and role `backing`;
  `part-b`'s row shows `sd-x` and role `member`; the unaffiliated `part-c` row
  ends with `-` for both the domain and role columns.

#### `show_secure_domains_renders_lineage` — 3 partitions (read-only)
- **Partitions:** `part-a` (backing), `part-b` (member), `part-c` (an
  outstanding reseal target that has not joined).
- **Writes:** `part-a` creates `sd-x`, `part-b` joins, `part-b` reseals to
  `part-c` (outstanding); `show_secure_domains` itself writes nothing.
- **Reads back:** stdout names the domain and its backing partition, with
  `members` and `hand-offs` blocks. The backing member shows role `backing` and
  `(root)`; `part-b` shows role `member` with `<- part-a` provenance; `part-b`'s
  join appears as a `consumed` hand-off and the reseal to `part-c` as
  `outstanding`.
