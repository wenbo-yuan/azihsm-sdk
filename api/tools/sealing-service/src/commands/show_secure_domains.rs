// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `show_secure_domains` — print per-domain membership and hand-off lineage.
//!
//! A read-only workspace command. It scans the versioned `secure-domain.json`
//! manifests beneath `secure-domains/` and renders, per domain, the backing
//! partition, the members with their join provenance, and the outstanding and
//! consumed hand-offs — so the reader can see which partition is the root of
//! the domain and how every other member joined. It reads metadata and artifact
//! names only: it never replays a partition, opens an HSM session, reads secret
//! contents, decodes backup blobs, or modifies the workspace. A missing or
//! invalid manifest is reported as an inventory error rather than silently
//! omitted.

use crate::error::Error;
use crate::error::Result;
use crate::manifest;
use crate::manifest::HandoffKind;
use crate::manifest::Role;
use crate::manifest::SecureDomainManifest;
use crate::util;
use crate::workspace::Workspace;

/// Run `show_secure_domains`.
pub fn run(ws: &Workspace) -> Result<()> {
    let names = util::list_subdirs(&ws.secure_domains_dir())?;

    if names.is_empty() {
        println!("(no secure domains)");
        return Ok(());
    }

    let mut first = true;
    for name in &names {
        let manifest_path = ws.secure_domain_manifest(name);
        if !manifest_path.exists() {
            return Err(Error::NotFound {
                what: "secure domain manifest",
                path: manifest_path,
            });
        }
        let domain: SecureDomainManifest = manifest::read(&manifest_path)?;

        if !first {
            println!();
        }
        first = false;
        print_domain(&domain);
    }

    Ok(())
}

/// Render one secure domain: header, members, and hand-offs.
fn print_domain(domain: &SecureDomainManifest) {
    let policy_short = short_digest(&domain.policy.sha384);
    println!(
        "SECURE DOMAIN  {}   (policy {policy_short}, backing {})",
        domain.name, domain.backing_partition.name,
    );

    println!("  members");
    for member in &domain.members {
        let provenance = match &member.source_partition {
            Some(source) => format!("<- {source}"),
            None => "(root)".to_owned(),
        };
        println!(
            "    {}  {}  {}  {}",
            member.partition,
            role_str(member.role),
            member.joined_via,
            provenance,
        );
    }

    println!("  hand-offs");
    if domain.handoffs.is_empty() {
        println!("    (none)");
    } else {
        for handoff in &domain.handoffs {
            let state = if handoff.consumed {
                "consumed"
            } else {
                "outstanding"
            };
            println!(
                "    {}  {}  {}  from {}  {state}",
                kind_str(handoff.kind),
                handoff.destination,
                handoff.created_by,
                handoff.source_partition,
            );
        }
    }
}

/// Display string for a partition's role within a domain.
fn role_str(role: Role) -> &'static str {
    match role {
        Role::Backing => "backing",
        Role::Member => "member",
    }
}

/// Display string for a hand-off kind.
fn kind_str(kind: HandoffKind) -> &'static str {
    match kind {
        HandoffKind::Remote => "remote",
        HandoffKind::Peer => "peer",
    }
}

/// The first four hex characters of a digest, with an ellipsis, for a compact
/// policy fingerprint. A short or empty digest is returned unchanged.
fn short_digest(sha384: &str) -> String {
    if sha384.len() <= 4 {
        sha384.to_owned()
    } else {
        format!("{}…", &sha384[..4])
    }
}
