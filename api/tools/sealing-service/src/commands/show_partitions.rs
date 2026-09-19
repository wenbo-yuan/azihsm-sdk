// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `show_partitions` — print a per-partition inventory table.
//!
//! A read-only workspace command. It scans the versioned `partition.json`
//! manifests beneath `partitions/`, correlates each partition with the secure
//! domain it belongs to (and its role within that domain), and prints a
//! deterministically sorted table. Each sealing key is listed with its recorded
//! key reports in brackets (`ska [repa, rep2]`). It reads metadata and artifact
//! names only: it never replays a partition, opens an HSM session, reads secret
//! contents, or modifies the workspace. A missing or invalid manifest is
//! reported as an inventory error rather than silently omitted.

use std::collections::HashMap;

use crate::error::Error;
use crate::error::Result;
use crate::manifest;
use crate::manifest::PartitionManifest;
use crate::manifest::Role;
use crate::manifest::SecureDomainManifest;
use crate::util;
use crate::workspace::Workspace;

/// One rendered row of the partition inventory.
struct Row {
    partition: String,
    authority_set: String,
    sealing_keys: String,
    secure_domain: String,
    sd_role: String,
}

/// Run `show_partitions`.
pub fn run(ws: &Workspace) -> Result<()> {
    let names = util::list_subdirs(&ws.partitions_dir())?;

    // Cache each domain manifest so a partition's role is resolved without
    // re-reading the same file per partition.
    let mut domains: HashMap<String, SecureDomainManifest> = HashMap::new();
    let mut rows: Vec<Row> = Vec::with_capacity(names.len());

    for name in &names {
        let manifest_path = ws.partition_manifest(name);
        if !manifest_path.exists() {
            // A directory under `partitions/` without a manifest is an
            // inventory error, not a silently-skipped entry.
            return Err(Error::NotFound {
                what: "partition manifest",
                path: manifest_path,
            });
        }
        let part: PartitionManifest = manifest::read(&manifest_path)?;

        let sealing_keys = if part.sealing_keys.is_empty() {
            "-".to_owned()
        } else {
            part.sealing_keys
                .iter()
                .map(|k| {
                    if k.reports.is_empty() {
                        k.name.clone()
                    } else {
                        let reports = k
                            .reports
                            .iter()
                            .map(|r| report_name(r))
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!("{} [{}]", k.name, reports)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        };

        let (secure_domain, sd_role) = match &part.secure_domain {
            Some(domain) => {
                let manifest = load_domain(ws, &mut domains, domain)?;
                let role = manifest
                    .members
                    .iter()
                    .find(|m| m.partition == part.name)
                    .map(|m| role_str(m.role).to_owned())
                    .unwrap_or_else(|| "-".to_owned());
                (domain.clone(), role)
            }
            None => ("-".to_owned(), "-".to_owned()),
        };

        rows.push(Row {
            partition: part.name,
            authority_set: part.authority_set,
            sealing_keys,
            secure_domain,
            sd_role,
        });
    }

    rows.sort_by(|a, b| a.partition.cmp(&b.partition));
    print_table(&rows);
    Ok(())
}

/// Load a domain manifest through the cache, reading it once.
fn load_domain<'a>(
    ws: &Workspace,
    cache: &'a mut HashMap<String, SecureDomainManifest>,
    domain: &str,
) -> Result<&'a SecureDomainManifest> {
    if !cache.contains_key(domain) {
        let manifest_path = ws.secure_domain_manifest(domain);
        if !manifest_path.exists() {
            return Err(Error::NotFound {
                what: "secure domain manifest",
                path: manifest_path,
            });
        }
        let manifest: SecureDomainManifest = manifest::read(&manifest_path)?;
        cache.insert(domain.to_owned(), manifest);
    }
    Ok(cache
        .get(domain)
        .expect("domain manifest inserted above is present"))
}

/// Display string for a partition's role within a domain.
fn role_str(role: Role) -> &'static str {
    match role {
        Role::Backing => "backing",
        Role::Member => "member",
    }
}

/// Extract the bare report name from a stored evidence artifact path
/// (`partitions/<p>/sealing-keys/<k>/evidence/<report>.bin` -> `<report>`).
fn report_name(artifact: &str) -> String {
    std::path::Path::new(artifact)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(artifact)
        .to_owned()
}

/// Render the inventory as a left-aligned, column-padded table.
fn print_table(rows: &[Row]) {
    const HEADERS: [&str; 5] = [
        "PARTITION",
        "AUTHORITY SET",
        "SEALING KEYS [REPORTS]",
        "SECURE DOMAIN",
        "SD ROLE",
    ];

    let mut widths = HEADERS.map(str::len);
    for row in rows {
        let cells = [
            &row.partition,
            &row.authority_set,
            &row.sealing_keys,
            &row.secure_domain,
            &row.sd_role,
        ];
        for (i, cell) in cells.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    println!("{}", pad_row(&HEADERS.map(str::to_owned), &widths));
    for row in rows {
        let cells = [
            row.partition.clone(),
            row.authority_set.clone(),
            row.sealing_keys.clone(),
            row.secure_domain.clone(),
            row.sd_role.clone(),
        ];
        println!("{}", pad_row(&cells, &widths));
    }
}

/// Pad each cell to its column width and join with two spaces, trimming
/// trailing whitespace on the last cell.
fn pad_row(cells: &[String; 5], widths: &[usize; 5]) -> String {
    let mut out = String::new();
    for (i, cell) in cells.iter().enumerate() {
        if i + 1 == cells.len() {
            out.push_str(cell);
        } else {
            out.push_str(&format!("{cell:<width$}  ", width = widths[i]));
        }
    }
    out
}
