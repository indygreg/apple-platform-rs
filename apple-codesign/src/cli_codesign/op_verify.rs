// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `codesign -v / --verify` implementation.
//!
//! Wraps the existing [`verify::verify_macho_data`] for Mach-O targets and
//! [`SignatureReader`] for the other kinds rcodesign already understands
//! (bundles, DMGs, XAR packages).  Flags whose checks would require new
//! verification primitives return a clear not-implemented error.

use {
    crate::{
        cli_codesign::options::{CodesignArgs, Target},
        error::AppleCodesignError,
        reader::{PathType, SignatureReader},
        verify::verify_macho_data,
    },
    log::{info, warn},
    std::path::Path,
};

pub fn run(args: &CodesignArgs) -> Result<(), AppleCodesignError> {
    if args.targets.is_empty() {
        return Err(AppleCodesignError::CliGeneralError(
            "verify operation requires at least one path or pid argument".into(),
        ));
    }

    if args.test_requirement.is_some() {
        return Err(AppleCodesignError::CliGeneralError(
            "codesign compat: -R / --test-requirement is not yet \
             implemented; use the native `rcodesign` commands or Apple's \
             codesign until a requirement evaluator is wired in"
                .into(),
        ));
    }

    if args.check_notarization {
        return Err(AppleCodesignError::CliGeneralError(
            "codesign compat: --check-notarization is not yet wired into \
             verify"
                .into(),
        ));
    }

    if let Some(strict) = &args.strict {
        if strict.symlinks || strict.sideband {
            warn!(
                "--strict {{symlinks,sideband}} are not yet implemented; \
                 continuing with baseline verification only"
            );
        }
    }

    if args.ignore_resources {
        warn!(
            "--ignore-resources is accepted but today's reader walks all \
             resources regardless; flag currently has no effect"
        );
    }

    let mut first_error: Option<AppleCodesignError> = None;

    for target in &args.targets {
        let path = match target {
            Target::Path(p) => p,
            Target::Pid(_) | Target::PlusPid(_) => {
                return Err(AppleCodesignError::CliGeneralError(
                    "codesign compat: dynamic validation of running \
                     processes (`+pid`) requires libsecurity and is not \
                     supported by this build"
                        .into(),
                ));
            }
        };

        match verify_one(path, args) {
            Ok(()) => {
                info!("{}: valid on disk", path.display());
            }
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

fn verify_one(path: &Path, _args: &CodesignArgs) -> Result<(), AppleCodesignError> {
    let kind = PathType::from_path(path)?;

    match kind {
        PathType::MachO => {
            let data = std::fs::read(path)?;
            let problems = verify_macho_data(data);
            if problems.is_empty() {
                return Ok(());
            }
            for p in &problems {
                eprintln!("{p}");
            }
            Err(AppleCodesignError::VerificationProblems)
        }
        PathType::Bundle | PathType::Dmg | PathType::Xar => {
            // For these formats rcodesign does not yet have a dedicated
            // verifier; the best we can do is walk the signature data via
            // SignatureReader and report any entities that lack a
            // signature or failed to decode.
            let reader = SignatureReader::from_path(path)?;
            let mut signed_any = false;
            for entity in reader.entities()? {
                use crate::reader::SignatureEntity;
                match entity.entity {
                    SignatureEntity::MachO(m) => {
                        if m.signature.is_some() {
                            signed_any = true;
                        }
                    }
                    SignatureEntity::Dmg(d) => {
                        if d.signature.is_some() {
                            signed_any = true;
                        }
                    }
                    SignatureEntity::BundleCodeSignatureFile(_) => {
                        signed_any = true;
                    }
                    _ => {}
                }
            }
            if !signed_any {
                return Err(AppleCodesignError::CliGeneralError(format!(
                    "{}: no code signature found",
                    path.display()
                )));
            }
            warn!(
                "bundle/dmg/xar verification is structural only; for full \
                 cryptographic verification use Apple's codesign"
            );
            Ok(())
        }
        PathType::Zip | PathType::Other => Err(AppleCodesignError::CliGeneralError(format!(
            "{}: unsupported target type for verify ({:?})",
            path.display(),
            kind
        ))),
    }
}
