// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `create_partition` — initialize a partition workspace and its attestation
//! artifacts.
//!
//! Implements the `create_partition` command contract from
//! `api/docs/design-sealing-service-cli.md`. It runs the provisioning flow
//! (see [`crate::provision`]), then issues the three PID attestation chains
//! from the authority set and persists the partition workspace atomically.
//!
//! Two mutually exclusive trust modes:
//!
//! * `--new-authority-set <name>` generates a fresh authority set and derives a
//!   backing-partition policy from this partition's identity;
//! * `--authority-set <name>` reuses an existing authority set and its single
//!   stored shared policy (validated against the set's SATA/POTA keys).

use azihsm_ddi_tbor_types::PART_POLICY_LEN;

use crate::authority;
use crate::authority::AuthoritySet;
use crate::cli::CreatePartitionArgs;
use crate::crypto;
use crate::crypto::certs;
use crate::crypto::policy;
use crate::error::Error;
use crate::error::Result;
use crate::manifest::Attestation;
use crate::manifest::AttestationAuthorities;
use crate::manifest::FileRef;
use crate::manifest::PartitionManifest;
use crate::manifest::PartitionRecovery;
use crate::manifest::SCHEMA_VERSION;
use crate::manifest::Session;
use crate::provision;
use crate::provision::Provisioned;
use crate::util;
use crate::workspace::Workspace;

/// Run `create_partition`.
pub fn run(ws: &Workspace, args: &CreatePartitionArgs) -> Result<()> {
    let partition = args.partition.as_str();

    // The partition workspace must not already exist.
    let partition_dir = ws.partition_dir(partition);
    if partition_dir.exists() {
        return Err(Error::AlreadyExists {
            what: "partition workspace",
            path: partition_dir,
        });
    }

    // Resolve the trust mode and prepare the authority set and policy source.
    let (authset, policy_override, new_mode, authority_set_name) = resolve_mode(ws, args)?;

    // Provision the partition against the HSM backend.
    let prov = provision::provision_partition(&authset, policy_override)?;

    let created_utc = util::now_rfc3339();

    // Persist the authority set on the new-authority-set path (writes
    // roots/, secrets/, policy.bin, authority-set.json); otherwise reference
    // the existing on-disk policy.
    let backing_policy = if new_mode {
        authset.persist(ws, &created_utc, &prov.policy)?
    } else {
        authority::policy_file_ref(ws, &authority_set_name)?
    };

    // Issue and persist the partition workspace.
    write_partition(
        ws,
        partition,
        &authority_set_name,
        &backing_policy,
        &created_utc,
        &authset,
        &prov,
    )?;

    print_summary(partition, &authority_set_name, new_mode, &prov);
    Ok(())
}

/// Resolve the two mutually exclusive trust modes into an authority set, an
/// optional verbatim policy, and the authority-set name.
fn resolve_mode(
    ws: &Workspace,
    args: &CreatePartitionArgs,
) -> Result<(AuthoritySet, Option<[u8; PART_POLICY_LEN]>, bool, String)> {
    match (&args.new_authority_set, &args.authority_set) {
        (Some(name), None) => {
            let dir = ws.authority_set_dir(name);
            if dir.exists() {
                return Err(Error::AlreadyExists {
                    what: "authority set",
                    path: dir,
                });
            }
            let authset = AuthoritySet::generate(name)?;
            Ok((authset, None, true, name.clone()))
        }
        (None, Some(name)) => {
            let authset = AuthoritySet::load(ws, name)?;

            // An authority set stores exactly one shared policy; reuse loads it
            // verbatim from the workspace container.
            let policy_path = ws.authority_set_policy(name);
            let bytes = util::read_file(&policy_path)?;
            if bytes.len() != PART_POLICY_LEN {
                return Err(Error::InvalidArgs(format!(
                    "stored policy for authority set `{name}` must be \
                     {PART_POLICY_LEN} bytes, got {}",
                    bytes.len()
                )));
            }
            let mut policy_bytes = [0u8; PART_POLICY_LEN];
            policy_bytes.copy_from_slice(&bytes);

            validate_policy_anchors(&policy_bytes, &authset)?;

            Ok((authset, Some(policy_bytes), false, name.clone()))
        }
        _ => Err(Error::InvalidArgs(
            "provide either --new-authority-set <name> or --authority-set <name>".to_owned(),
        )),
    }
}

/// Confirm the stored policy's SATA and POTA public keys match the authority
/// set that must issue this partition's chains and sign its PTA chain.
fn validate_policy_anchors(policy_bytes: &[u8], authset: &AuthoritySet) -> Result<()> {
    let sata = policy::sata_raw_from_policy(policy_bytes)?;
    let pota = policy::pota_raw_from_policy(policy_bytes)?;
    if sata != authset.sata.raw_pub() {
        return Err(Error::PolicyMismatch(
            "policy SATA public key does not match authority set".to_owned(),
        ));
    }
    if pota != authset.pota.raw_pub() {
        return Err(Error::PolicyMismatch(
            "policy POTA public key does not match authority set".to_owned(),
        ));
    }
    Ok(())
}

/// Issue the three PID chains and persist every partition artifact and the
/// partition manifest.
fn write_partition(
    ws: &Workspace,
    partition: &str,
    authority_set_name: &str,
    backing_policy: &FileRef,
    created_utc: &str,
    authset: &AuthoritySet,
    prov: &Provisioned,
) -> Result<()> {
    // Directories.
    util::create_dir_all(&ws.partition_dir(partition))?;
    util::create_dir_all(&ws.partition_secrets_dir(partition))?;
    util::create_dir_all(&ws.partition_attestation_dir(partition))?;
    util::create_dir_all(&ws.partition_attestation_authorities_dir(partition))?;
    util::create_dir_all(&ws.partition_sealing_keys_dir(partition))?;

    // Session credential.
    let co_psk_path = ws.partition_co_psk(partition);
    util::write_secret(&co_psk_path, &prov.co_psk)?;

    // PID public key.
    let pid_pub_der = crypto::public_key_der(&prov.pid_pub)?;
    let pid_pub_path = ws.partition_pid_public_key(partition);
    util::write_atomic(&pid_pub_path, &pid_pub_der)?;

    // The three PID chains, each root -> leaf certifying the PID public key.
    let manufacturer_chain = certs::make_chain(&authset.manufacturer, &prov.pid_pub);
    let owner_chain = certs::make_chain(&authset.owner, &prov.pid_pub);
    let partition_owner_chain = certs::make_chain(&authset.sata, &prov.pid_pub);

    let manufacturer_paths = write_chain(ws, partition, "manufacturer-chain", &manufacturer_chain)?;
    let owner_paths = write_chain(ws, partition, "owner-chain", &owner_chain)?;
    let partition_owner_paths = write_chain(
        ws,
        partition,
        "partition-owner-chain",
        &partition_owner_chain,
    )?;

    // Public authority roots copied into the attestation area (identical to
    // each chain's self-signed root).
    let authorities_dir = ws.partition_attestation_authorities_dir(partition);
    let manufacturer_root = authorities_dir.join("manufacturer-root.der");
    let owner_root = authorities_dir.join("owner-root.der");
    let sata_root = authorities_dir.join("sata-root.der");
    util::write_atomic(&manufacturer_root, &manufacturer_chain.root_der)?;
    util::write_atomic(&owner_root, &owner_chain.root_der)?;
    util::write_atomic(&sata_root, &partition_owner_chain.root_der)?;

    // Emulator recovery material (transient emulator partition only).
    let recovery = if cfg!(feature = "emu") {
        util::create_dir_all(&ws.partition_recovery_dir(partition))?;
        let mach_seed_path = ws.partition_mach_seed(partition);
        let backup_path = ws.partition_part_final_backup(partition);
        let identity_path = ws.partition_identity(partition);
        util::write_atomic(&mach_seed_path, &prov.mach_seed)?;
        util::write_atomic(&backup_path, &prov.local_mk_backup)?;
        util::write_secret(&identity_path, &provision::export_identity()?)?;
        Some(PartitionRecovery {
            mach_seed: rel(ws, &mach_seed_path)?,
            part_final_local_mk_backup: rel(ws, &backup_path)?,
            identity: rel(ws, &identity_path)?,
        })
    } else {
        None
    };

    let manifest = PartitionManifest {
        schema_version: SCHEMA_VERSION,
        kind: "partition".to_owned(),
        name: partition.to_owned(),
        created_utc: created_utc.to_owned(),
        pid: hex::encode(&prov.pid),
        pid_public_key: FileRef {
            path: rel(ws, &pid_pub_path)?,
            sha384: util::sha384_hex(&pid_pub_der),
        },
        authority_set: authority_set_name.to_owned(),
        backing_policy: backing_policy.clone(),
        session: Session {
            co_psk: rel(ws, &co_psk_path)?,
            psk_rotated: true,
        },
        recovery,
        attestation: Attestation {
            authorities: AttestationAuthorities {
                manufacturer_root: rel(ws, &manufacturer_root)?,
                owner_root: rel(ws, &owner_root)?,
                sata_root: rel(ws, &sata_root)?,
            },
            manufacturer_chain: manufacturer_paths,
            owner_chain: owner_paths,
            partition_owner_chain: partition_owner_paths,
        },
        sealing_keys: Vec::new(),
        secure_domain: None,
    };
    crate::manifest::write(&ws.partition_manifest(partition), &manifest)?;
    Ok(())
}

/// Write a root -> leaf chain under `attestation/<chain>/` and return its
/// `[root, leaf]` relative paths.
fn write_chain(
    ws: &Workspace,
    partition: &str,
    chain: &str,
    generated: &certs::GeneratedChain,
) -> Result<Vec<String>> {
    let dir = ws.partition_attestation_chain_dir(partition, chain);
    util::create_dir_all(&dir)?;
    let root_path = dir.join("root.der");
    let leaf_path = dir.join("leaf.der");
    util::write_atomic(&root_path, &generated.root_der)?;
    util::write_atomic(&leaf_path, &generated.leaf_der)?;
    Ok(vec![rel(ws, &root_path)?, rel(ws, &leaf_path)?])
}

fn print_summary(partition: &str, authority_set: &str, new_mode: bool, prov: &Provisioned) {
    let mode = if new_mode {
        "new authority set"
    } else {
        "reused authority set"
    };
    println!("create_partition: initialized `{partition}`");
    println!("  authority set: {authority_set} ({mode})");
    println!("  pid:           {}", hex::encode(&prov.pid));
    println!("  flavor:        {}", crate::flavor::FLAVOR);
}

fn rel(ws: &Workspace, abs: &std::path::Path) -> Result<String> {
    ws.relative(abs)
        .map_err(|err| Error::Internal(err.to_string()))
}
