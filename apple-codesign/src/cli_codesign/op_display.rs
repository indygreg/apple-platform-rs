// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `codesign -d / --display` implementation.
//!
//! Formats the [`FileEntity`]s returned by [`SignatureReader`] into a
//! human-readable summary.  The output is **not** byte-identical to
//! Apple's codesign; it is optimized to be informative and stable.  For
//! deep inspection (verbose >= 4) we fall back to the YAML that rcodesign's
//! own `print-signature-info` emits.

use {
    crate::{
        cli_codesign::options::{CodesignArgs, Target},
        error::AppleCodesignError,
        reader::{CodeSignature, FileEntity, SignatureEntity, SignatureReader},
    },
    log::warn,
    std::{
        io::Write,
        path::{Path, PathBuf},
    },
};

pub fn run(args: &CodesignArgs) -> Result<(), AppleCodesignError> {
    if args.targets.is_empty() {
        return Err(AppleCodesignError::CliGeneralError(
            "display operation requires at least one path or pid argument".into(),
        ));
    }

    if args.extract_certificates.is_some() {
        return Err(AppleCodesignError::CliGeneralError(
            "codesign compat: --extract-certificates is not yet implemented".into(),
        ));
    }

    if args.file_list.is_some() {
        return Err(AppleCodesignError::CliGeneralError(
            "codesign compat: --file-list during display is not yet implemented".into(),
        ));
    }

    let mut first_error: Option<AppleCodesignError> = None;

    for target in &args.targets {
        let path = match target {
            Target::Path(p) => p,
            Target::Pid(_) | Target::PlusPid(_) => {
                return Err(AppleCodesignError::CliGeneralError(
                    "codesign compat: dynamic display of running processes \
                     (`+pid`) is not supported by this build"
                        .into(),
                ));
            }
        };

        match display_one(path, args) {
            Ok(()) => {}
            Err(e) => {
                if args.continue_on_error {
                    eprintln!("{}: {}", path.display(), e);
                    first_error.get_or_insert(e);
                } else {
                    return Err(e);
                }
            }
        }
    }

    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn display_one(path: &Path, args: &CodesignArgs) -> Result<(), AppleCodesignError> {
    let reader = SignatureReader::from_path(path)?;
    let entities = reader.entities()?;

    // Apple's codesign -d resolves the full symlink chain (and on macOS
    // expands /tmp into /private/tmp) before emitting `Executable=...`,
    // so we match that.  Fall back to the original argv path if
    // canonicalization is impossible — for instance when the user
    // points at a path that doesn't exist on disk and we are operating
    // on data we already loaded.
    let display_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    if args.verbose >= 4 {
        serde_yaml::to_writer(std::io::stdout(), &entities)?;
        return Ok(());
    }

    for entity in &entities {
        print_entity(&display_path, entity, args.verbose);
    }

    // Side-channel outputs requested in codesign-compat style.
    if let Some(req_arg) = &args.requirements {
        extract_requirements(&entities, req_arg)?;
    }

    if let Some(dest) = &args.display_entitlements {
        // --entitlements during display uses the path slot, not the sign slot.
        let _ = args.entitlements.as_deref();
        extract_entitlements(&entities, dest, args.display_xml, args.display_der)?;
    }

    Ok(())
}

fn print_entity(root: &Path, entity: &FileEntity, verbose: u8) {
    match &entity.entity {
        SignatureEntity::MachO(m) => {
            let display_path = match &entity.sub_path {
                Some(sub) => format!("{}::{}", root.display(), sub),
                None => root.display().to_string(),
            };
            println!("Executable={display_path}");
            if let Some(sig) = &m.signature {
                print_code_signature(sig, verbose);
            } else {
                println!("  (no code signature)");
            }
        }
        SignatureEntity::Dmg(d) => {
            println!("DMG={}", root.display());
            if let Some(sig) = &d.signature {
                print_code_signature(sig, verbose);
            } else {
                println!("  (no code signature)");
            }
        }
        SignatureEntity::BundleCodeSignatureFile(kind) => {
            let label = match kind {
                crate::reader::CodeSignatureFile::ResourcesXml(_) => "CodeResources",
                crate::reader::CodeSignatureFile::NotarizationTicket => "NotarizationTicket",
                crate::reader::CodeSignatureFile::Other => "Other",
            };
            let sub = entity.sub_path.as_deref().unwrap_or("");
            println!("Bundle={} kind={label} sub_path={sub}", root.display());
        }
        SignatureEntity::XarMember(_) | SignatureEntity::XarTableOfContents(_) => {
            println!("XarEntity={} sub_path={:?}", root.display(), entity.sub_path);
        }
        SignatureEntity::Other => {}
    }
}

fn print_code_signature(sig: &CodeSignature, verbose: u8) {
    if let Some(cd) = &sig.code_directory {
        println!("Identifier={}", cd.identifier);
        if let Some(team) = &cd.team_name {
            println!("TeamIdentifier={team}");
        }
        println!(
            "CodeDirectory version={} flags={} hashes={} digest={}",
            cd.version, cd.flags, cd.code_digests_count, cd.digest_type
        );
        if let Some(runtime) = &cd.runtime_version {
            println!("Runtime={runtime}");
        }
    }
    if !sig.alternative_code_directories.is_empty() {
        println!(
            "AlternateCodeDirectories={}",
            sig.alternative_code_directories.len()
        );
    }

    if let Some(cms) = &sig.cms {
        println!("Signed (CMS present, {} blob(s))", sig.blob_count);
        if verbose >= 2 {
            for (i, signer) in cms.signers.iter().enumerate() {
                println!("Authority[{i}]={}", signer.issuer);
            }
        }
    } else {
        println!("Signed (ad-hoc)");
    }

    if verbose >= 1 && !sig.code_requirements.is_empty() {
        println!("CodeRequirements:");
        for r in &sig.code_requirements {
            println!("  {r}");
        }
    }

    if verbose >= 2 && !sig.entitlements_plist.is_empty() {
        println!("Entitlements:");
        for line in &sig.entitlements_plist {
            println!("  {line}");
        }
    }
}

fn extract_requirements(
    entities: &[FileEntity],
    arg: &crate::cli_codesign::options::RequirementArg,
) -> Result<(), AppleCodesignError> {
    use crate::cli_codesign::options::RequirementArg;

    let sig = first_code_signature(entities).ok_or_else(|| {
        AppleCodesignError::CliGeneralError(
            "cannot extract requirements: no code signature found".into(),
        )
    })?;
    if sig.code_requirements.is_empty() {
        warn!("no internal requirements to extract");
        return Ok(());
    }

    let text = sig.code_requirements.join("\n") + "\n";

    match arg {
        RequirementArg::Stdin | RequirementArg::Source(_) => {
            // `-r-` during display means stdout; any other form that
            // is not a file path is accepted here as "write to stdout".
            print!("{text}");
        }
        RequirementArg::Path(p) if p.as_os_str() == "-" => {
            print!("{text}");
        }
        RequirementArg::Path(p) => {
            std::fs::write(p, text)?;
        }
    }
    Ok(())
}

fn extract_entitlements(
    entities: &[FileEntity],
    dest: &PathBuf,
    want_xml: bool,
    want_der: bool,
) -> Result<(), AppleCodesignError> {
    let sig = first_code_signature(entities).ok_or_else(|| {
        AppleCodesignError::CliGeneralError(
            "cannot extract entitlements: no code signature found".into(),
        )
    })?;

    // codesign says "if you pass in both then DER will be printed".  We
    // match that.  Default (neither --xml nor --der) picks whichever is
    // present, preferring the DER rendering since that is what newer code
    // signatures carry authoritatively.
    let source_lines = if want_der {
        &sig.entitlements_der_plist
    } else if want_xml {
        &sig.entitlements_plist
    } else if !sig.entitlements_der_plist.is_empty() {
        &sig.entitlements_der_plist
    } else {
        &sig.entitlements_plist
    };

    if source_lines.is_empty() {
        // codesign treats "no entitlements" as a non-error.
        return Ok(());
    }

    let text = source_lines.join("\n") + "\n";
    if dest.as_os_str() == "-" {
        let mut out = std::io::stdout().lock();
        out.write_all(text.as_bytes())?;
    } else {
        std::fs::write(dest, text)?;
    }
    Ok(())
}

fn first_code_signature(entities: &[FileEntity]) -> Option<&CodeSignature> {
    for entity in entities {
        match &entity.entity {
            SignatureEntity::MachO(m) => {
                if let Some(s) = &m.signature {
                    return Some(s);
                }
            }
            SignatureEntity::Dmg(d) => {
                if let Some(s) = &d.signature {
                    return Some(s);
                }
            }
            _ => {}
        }
    }
    None
}
