<!-- Copyright (c) Microsoft Corporation. All rights reserved. -->

# Sealing Service CLI - Demo Cheatsheet

Source: local `wenboy/cmd_tool` branch at commit
`c46e70f39b881dd7cd501518ff2e9b49956a0515`.

Commands below are for **Linux/WSL Bash**, from the SDK repository root.
This is an emulator demo, not a hardware-provisioning procedure.
Command syntax and prerequisites were checked against the branch's CLI and
handlers; this cheatsheet was not executed against a local SDK build.
Start with fresh state: the local branch uses an updated evidence-bundle schema.

## 0. Build and start a fresh demo

In a checkout of `wenboy/cmd_tool`, with the SDK build prerequisites installed:

```bash
cargo build -p azihsm_sealing_service --features emu
BIN="$PWD/target/debug/azihsm-sealing-service"
"$BIN" --version

# A new private directory gives each demo an isolated state file.
DEMO_DIR="$(mktemp -d)" || exit 1
export AZIHSM_SEALING_STATE_PATH="$DEMO_DIR/sealing-state.bin"
printf 'Demo state: %s\n' "$AZIHSM_SEALING_STATE_PATH"
```

**Presenter notes:** The version should identify the `emu` flavor. Every command
is a separate process. Authority material, partition recovery artifacts, masked
keys, evidence, and domain manifests persist inside the same binary state file.
There is no config-file argument or `--working-dir` option in this version.
Keep this shell open, or export the same state-file path in subsequent shells.
Run commands sequentially and stop if any command fails.

## Case 1: A creates a remote backup; B restores it

Run this case immediately after the build and fresh-state setup above.
Only two partitions are needed; there is no relay or resealing. The blocks below
use one Bash shell and two separate state files to demonstrate copying between
the A and B execution contexts on the emulator.

**Important dependency:** A cannot create a backup for B until B has generated
its sealing key and evidence. With the current CLI, exchange the complete state
container; there is no standalone evidence export/import or workspace merge.

```text
A: provision and attest A
    --copy state to B-->
B: provision and attest B using A's authority set
    --copy updated state back to A-->
A: create_remote_backup addressed to B
    --copy updated state to B-->
B: restore_remote_backup
```

### Stage 1. On A: provision A and generate its evidence

```bash
STATE_A="$DEMO_DIR/partition-a.bin"
STATE_B="$DEMO_DIR/partition-b.bin"
export AZIHSM_SEALING_STATE_PATH="$STATE_A"

"$BIN" create_partition --partition a --new-authority-set direct-auth
"$BIN" create_sd_sealing_key --partition a --sealing-key sk
"$BIN" key_report --partition a --sealing-key sk --report report
"$BIN" show_partitions
```

**Show:** Only A exists, with its sealing key and report. No domain exists yet.

### Transfer 1. Copy A's state file to B

```bash
cp -- "$STATE_A" "$STATE_B"
chmod 600 "$STATE_B"
```

### Stage 2. On B: provision B and generate its evidence

```bash
export AZIHSM_SEALING_STATE_PATH="$STATE_B"

"$BIN" create_partition --partition b --authority-set direct-auth
"$BIN" create_sd_sealing_key --partition b --sealing-key sk
"$BIN" key_report --partition b --sealing-key sk --report report
"$BIN" show_partitions
```

**Show:** Both partitions have a sealing key and evidence; neither belongs to
a secure domain yet. B reuses A's authority set and backing policy from the
copied state file.

### Transfer 2. Copy B's updated state file back to A

```bash
cp -- "$STATE_B" "$STATE_A"
chmod 600 "$STATE_A"
```

**Explain:** This returns B's receiver evidence to A. It replaces A's older
snapshot with the latest complete workspace; it does not merge two workspaces.

### Stage 3. On A: create the domain and a remote backup for B

```bash
export AZIHSM_SEALING_STATE_PATH="$STATE_A"

"$BIN" create_remote_backup \
    --partition a --secure-domain direct-sd --sealing-key sk \
    --receiver-evidence b/sk/report

"$BIN" show_secure_domains
```

**Show:** `a` is the backing member of `direct-sd`. The remote hand-off to `b`
is outstanding; `b` is not a member yet.

**Explain:** A uses its own sealing key and B's attested public key to produce
the remote backup. `b/sk/report` is an internal evidence reference, not a file.
The CLI saves the backup inside the shared state container automatically.

### Transfer 3. Copy A's updated state file to B

```bash
cp -- "$STATE_A" "$STATE_B"
chmod 600 "$STATE_B"
```

**Explain:** This transfers the remote backup, domain metadata, and A's sender
evidence together. Do not recreate B or regenerate its sealing key: this backup
is addressed to the key B generated in Stage 2.

### Stage 4. On B: restore the backup using A's evidence

```bash
export AZIHSM_SEALING_STATE_PATH="$STATE_B"

"$BIN" restore_remote_backup \
    --partition b --secure-domain direct-sd --sealing-key sk \
    --sender-evidence a/sk/report

"$BIN" show_partitions
"$BIN" show_secure_domains
```

**Show:** `a` remains the backing member; `b` is now a member of the same domain,
joined through `restore_remote_backup` with source `a`. The remote hand-off
to `b` is marked consumed.

**Explain:** B uses its own sealing key to open the backup and A's evidence
to authenticate the sender. B receives its own local recovery pair.
Do not repeat either operation on this completed state: domain creation and
member admission are not refresh commands.

**Copying between actual demo hosts:** Build the same emulator version on both
hosts, replace each `cp` with an authenticated transfer such as `scp`, and set
`AZIHSM_SEALING_STATE_PATH` to the destination file on the receiving host.
`BIN`, `STATE_A`, and `STATE_B` are shell variables, not contents of the file;
set them to the appropriate local paths in each terminal. Preserve owner-only
permissions. This is a whole-workspace emulator hand-off, not a hardware
partition migration or a production artifact-sharing design: the file includes
both partitions' recovery material and authority secrets.

**Keep one current snapshot:** Do not run concurrent operations on the two
copies. After B restores, B's copy is current; A's copy still shows B's hand-off
as outstanding. Copy B's final file back to A before doing further work on A.

## Case 2: A creates a remote backup; B reseals; C restores

This case uses only three partitions and no peer-backup or local-recovery
operations. A creates the domain, B acts as a relay without joining, and C
restores the resealed backup to join A's domain.

As in Case 1, use one Bash shell with separate emulator state files. Build the
emulator and set `BIN` as shown in section 0. Start with fresh state, independent
of Case 1:

```bash
CASE2_DIR="$(mktemp -d)" || exit 1
STATE_A="$CASE2_DIR/partition-a.bin"
STATE_B="$CASE2_DIR/partition-b.bin"
STATE_C="$CASE2_DIR/partition-c.bin"
```

The initial transfers collect all three partitions' evidence before backup
operations begin. Every copy carries the latest complete workspace.

```text
A: provision and attest A
    --copy file A to B-->
B: provision and attest B
    --copy file B to C-->
C: provision and attest C
    --copy file C to A-->
A: create remote backup addressed to B
    --copy file A to B-->
B: reseal remote backup addressed to C (does NOT join)
    --copy file B to C-->
C: restore remote backup (joins the domain)
```

### Stage 1. On A: provision A and generate its evidence

```bash
export AZIHSM_SEALING_STATE_PATH="$STATE_A"

"$BIN" create_partition --partition a --new-authority-set reseal-auth
"$BIN" create_sd_sealing_key --partition a --sealing-key sk
"$BIN" key_report --partition a --sealing-key sk --report report
"$BIN" show_partitions
```

**Show:** Only A exists, with a sealing key and report. No domain exists yet.

### Transfer 1. Copy A's state file to B

```bash
cp -- "$STATE_A" "$STATE_B"
chmod 600 "$STATE_B"
```

### Stage 2. On B: provision B and generate its evidence

```bash
export AZIHSM_SEALING_STATE_PATH="$STATE_B"

"$BIN" create_partition --partition b --authority-set reseal-auth
"$BIN" create_sd_sealing_key --partition b --sealing-key sk
"$BIN" key_report --partition b --sealing-key sk --report report
"$BIN" show_partitions
```

**Show:** A and B are provisioned under the same authority set and policy;
neither belongs to a domain yet.

### Transfer 2. Copy B's updated state file to C

```bash
cp -- "$STATE_B" "$STATE_C"
chmod 600 "$STATE_C"
```

### Stage 3. On C: provision C and generate its evidence

```bash
export AZIHSM_SEALING_STATE_PATH="$STATE_C"

"$BIN" create_partition --partition c --authority-set reseal-auth
"$BIN" create_sd_sealing_key --partition c --sealing-key sk
"$BIN" key_report --partition c --sealing-key sk --report report
"$BIN" show_partitions
```

**Show:** All three partitions have sealing keys and reports, share the same
authority set and policy, and have no domain membership.

### Transfer 3. Copy C's updated state file back to A

```bash
cp -- "$STATE_C" "$STATE_A"
chmod 600 "$STATE_A"
```

**Explain:** A now has B's receiver evidence. The workspace also includes C's
evidence, which B will need later when resealing to C.

### Stage 4. On A: create a remote backup addressed to B

```bash
export AZIHSM_SEALING_STATE_PATH="$STATE_A"

"$BIN" create_remote_backup \
    --partition a --secure-domain reseal-sd --sealing-key sk \
    --receiver-evidence b/sk/report

"$BIN" show_secure_domains
```

**Show:** A is the backing member of `reseal-sd`. The remote hand-off to B is
outstanding. B and C are not members.

### Transfer 4. Copy A's updated state file to B

```bash
cp -- "$STATE_A" "$STATE_B"
chmod 600 "$STATE_B"
```

### Stage 5. On B: reseal the remote backup to C without joining

```bash
export AZIHSM_SEALING_STATE_PATH="$STATE_B"

"$BIN" reseal_remote_backup \
    --partition b --secure-domain reseal-sd --sealing-key sk \
    --sender-evidence a/sk/report \
    --receiver-evidence c/sk/report

"$BIN" show_secure_domains
"$BIN" show_partitions
```

**Show:** A is still the only member. A new remote hand-off to C is outstanding,
sourced by B. B still has no domain membership, and its inbound hand-off remains
outstanding.

**Explain:** B uses its own sealing key to open the backup from A, authenticates
A using `a/sk/report`, and reseals the same BKS3 to C's attested key. Do **not**
run `restore_remote_backup` on B; B is a reseal-only relay in this case.

### Transfer 5. Copy B's updated state file to C

```bash
cp -- "$STATE_B" "$STATE_C"
chmod 600 "$STATE_C"
```

### Stage 6. On C: restore the resealed remote backup

```bash
export AZIHSM_SEALING_STATE_PATH="$STATE_C"

"$BIN" restore_remote_backup \
    --partition c --secure-domain reseal-sd --sealing-key sk \
    --sender-evidence b/sk/report

"$BIN" show_partitions
"$BIN" show_secure_domains
```

**Show:** A is the backing member; C is a member joined through
`restore_remote_backup` with source B. B is not a member. C's hand-off is
consumed; the original hand-off addressed to B remains outstanding.

**Explain:** C opens the backup with its own sealing key and authenticates
the immediate sender, B. Use `b/sk/report`, **not** `a/sk/report`, for this
restore.

**Keep one current snapshot:** C's file is now current. Do not continue from
A's or B's older copy without first copying C's final state there. As in
Case 1, actual demo hosts require the same emulator build, local environment
variables, and authenticated file transfers in place of `cp`. The complete
container includes secrets; this is not a hardware migration procedure.

## Case 3: B creates a peer backup; C restores it

Continue from **completed Case 1**, where A is the backing member and B has
joined `direct-sd`. Do not use Case 2's state: B is only a relay there and
cannot create a peer backup. This operation requires the domain policy to
permit peer cloning (`allow_peer_cloning`).

Use the same Bash shell and `BIN` from the earlier setup. The paths below
explicitly select Case 1's final B snapshot, even if Case 2 changed `STATE_B`.
Do not start with an empty state file or create another domain.

```bash
PEER_STATE_B="$DEMO_DIR/partition-b.bin"
PEER_STATE_C="$DEMO_DIR/partition-c.bin"
```

```text
B: check existing membership in A's domain
    --copy file B to C-->
C: provision and attest C
    --copy updated file C to B-->
B: create_peer_backup addressed to C
    --copy updated file B to C-->
C: restore_peer_backup using B's evidence
```

### Stage 1. On B: confirm the starting domain membership

```bash
export AZIHSM_SEALING_STATE_PATH="$PEER_STATE_B"

"$BIN" show_partitions
"$BIN" show_secure_domains
```

**Show:** A is the backing member of `direct-sd`; B is a member joined through
`restore_remote_backup`. C does not exist yet.

### Transfer 1. Copy B's current state file to C

```bash
cp -- "$PEER_STATE_B" "$PEER_STATE_C"
chmod 600 "$PEER_STATE_C"
```

### Stage 2. On C: provision C and generate its evidence

```bash
export AZIHSM_SEALING_STATE_PATH="$PEER_STATE_C"

"$BIN" create_partition --partition c --authority-set direct-auth
"$BIN" create_sd_sealing_key --partition c --sealing-key sk
"$BIN" key_report --partition c --sealing-key sk --report report
"$BIN" show_partitions
```

**Show:** C has a sealing key and report under the same authority set and
policy as A and B, but has not joined the domain.

### Transfer 2. Copy C's updated state file back to B

```bash
cp -- "$PEER_STATE_C" "$PEER_STATE_B"
chmod 600 "$PEER_STATE_B"
```

**Explain:** B now has C's receiver evidence. This replaces B's old snapshot
with the latest complete workspace; it does not merge separate workspaces.

### Stage 3. On B: create a peer backup addressed to C

```bash
export AZIHSM_SEALING_STATE_PATH="$PEER_STATE_B"

"$BIN" create_peer_backup \
    --partition b --secure-domain direct-sd --sealing-key sk \
    --peer-evidence c/sk/report

"$BIN" show_secure_domains
```

**Show:** A and B remain the only members. A peer hand-off to C is outstanding,
with B as its source. Creating this backup does not make C a member.

**Explain:** Unlike the reseal-only B in Case 2, this B is already a member.
It recovers the domain's BKS3 from its own local recovery material and seals
it to C's attested key. No new domain is created. On create,
`--peer-evidence` identifies the **destination**, C.

### Transfer 3. Copy B's updated state file to C

```bash
cp -- "$PEER_STATE_B" "$PEER_STATE_C"
chmod 600 "$PEER_STATE_C"
```

### Stage 4. On C: restore the peer backup using B's evidence

```bash
export AZIHSM_SEALING_STATE_PATH="$PEER_STATE_C"

"$BIN" restore_peer_backup \
    --partition c --secure-domain direct-sd --sealing-key sk \
    --peer-evidence b/sk/report

"$BIN" show_partitions
"$BIN" show_secure_domains
```

**Show:** A remains the backing member; B and C are members of `direct-sd`.
C joined through `restore_peer_backup` with source B, has its own local
recovery pair, and its peer hand-off is marked consumed.

**Explain:** On restore, `--peer-evidence` identifies the **source**, B, not
the destination C or the backing member A. C uses its own sealing key to
open the backup and B's evidence to authenticate the sender.

**Keep one current snapshot:** C's file is now current; A's and B's files are
older snapshots. Copy C's final file to the next execution context before
continuing. Do not repeat C's admission or rerun this case on completed state.
The same whole-workspace secret-handling and emulator-only restrictions from
Case 1 apply; use authenticated transfers instead of `cp` between demo hosts.

## Separate case: Minimal self-backup and local recovery

Use another **fresh state file**:

```bash
SELF_DIR="$(mktemp -d)" || exit 1
export AZIHSM_SEALING_STATE_PATH="$SELF_DIR/sealing-state.bin"

"$BIN" create_partition --partition solo --new-authority-set self-auth
"$BIN" create_sd_sealing_key --partition solo --sealing-key sk
"$BIN" key_report --partition solo --sealing-key sk --report report

"$BIN" create_remote_backup \
    --partition solo --secure-domain self-sd --sealing-key sk \
    --receiver-evidence solo/sk/report

"$BIN" restore_local_backup --partition solo --secure-domain self-sd
"$BIN" show_secure_domains
```

**Expected:** One backing member, `solo`, with self-backup scope.
The self hand-off is marked consumed on creation. Do **not** follow it with
`restore_remote_backup`: `solo` already belongs to the domain.

## Demo pitfalls

| Symptom / mistake | Correct action |
|---|---|
| Repeating `create_remote_backup` on an existing domain | It creates a new domain, not another backup for an existing one. Use reseal or peer backup for subsequent destinations. |
| Following the README's self-backup example with another create for the same domain | Those examples cannot run consecutively as written; use a fresh state file or one of the continuous flows above. |
| Wrong sender evidence after reseal | Restore must authenticate the resealing partition, not the original backing partition. |
| Resealing without a backup addressed to the operating partition | Create that inbound remote hand-off first; use its recipient sealing key. |
| Peer backup from a non-member | Restore/join the source first, or use reseal for a relay-only flow. |
| Repeating a restore after joining | Rejected: remote/peer restore admits a new member; use local restore to refresh an existing member. |
| Missing partitions after opening another terminal | Export the exact same `AZIHSM_SEALING_STATE_PATH`. |
| Looking for backup files beside the state file | The named artifacts are inside the binary container, not loose files. |
| Trying this multi-partition emulator script on hardware | Do not: provisioning resets the selected backend partition and the implementation selects the first advertised partition. Logical names are not hardware selectors. |

The state container holds secrets: do not share or commit it. Use a fresh
private directory to restart the emulator demo rather than deleting old state.
Inventory commands show persisted workspace state, not an independent hardware
health check or proof that arbitrary application crypto operations work.

## Source references

- [CLI arguments](src/cli.rs)
- [Command handlers](src/commands)
- [Provisioning and reset behavior](src/provision.rs)
