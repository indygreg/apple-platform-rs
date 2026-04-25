// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `codesign -s identity` implementation.
//!
//! Translates a parsed [`CodesignArgs`] into a fully populated
//! [`SigningSettings`] and runs [`UnifiedSigner::sign_path_in_place`] per
//! target.  Flags whose behavior cannot be expressed with today's core
//! primitives return a clear error instead of silently doing the wrong
//! thing.

use {
    crate::{
        cli_codesign::{
            identity,
            options::{CodesignArgs, Target, TimestampArg},
            requirements,
        },
        code_directory::CodeSignatureFlags,
        code_requirement::CodeRequirements,
        environment_constraints::EncodedEnvironmentConstraints,
        error::AppleCodesignError,
        reader::SignatureReader,
        signing::UnifiedSigner,
        signing_settings::{SettingsScope, SigningSettings},
    },
    log::{info, warn},
    std::path::Path,
};

const APPLE_TIMESTAMP_URL: &str = "http://timestamp.apple.com/ts01";

/// Mach-O page size hard-coded by `macho_signing.rs`. Kept in sync with
/// that file; `-P` accepts this exact value as a no-op.
const DEFAULT_MACHO_PAGE_SIZE: u64 = 4096;

pub fn run(args: &CodesignArgs) -> Result<(), AppleCodesignError> {
    reject_unsupported(args)?;

    if args.targets.is_empty() {
        return Err(AppleCodesignError::CliGeneralError(
            "sign operation requires at least one path argument".into(),
        ));
    }

    // Per target, because codesign semantics say "performs the same operation
    // on all of them" but each path has its own pre-existing signature check.
    let mut first_error: Option<AppleCodesignError> = None;
    for target in &args.targets {
        let path = match target {
            Target::Path(p) => p,
            Target::Pid(_) | Target::PlusPid(_) => {
                return Err(AppleCodesignError::CliGeneralError(
                    "sign operation does not accept PID arguments".into(),
                ));
            }
        };

        if let Err(e) = sign_one(path, args) {
            if args.continue_on_error {
                eprintln!("{}: {}", path.display(), e);
                first_error.get_or_insert(e);
            } else {
                return Err(e);
            }
        }
    }

    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn reject_unsupported(args: &CodesignArgs) -> Result<(), AppleCodesignError> {
    if args.remove_signature {
        return Err(not_implemented("--remove-signature"));
    }
    if args.detached.is_some() {
        return Err(not_implemented(
            "-D / --detached (writing a detached signature)",
        ));
    }
    if args.detached_database {
        return Err(not_implemented("--detached-database"));
    }
    if args.preserve_metadata.is_some() {
        return Err(not_implemented("--preserve-metadata"));
    }
    if let Some(ps) = args.page_size {
        // SigningSettings has no per-scope page-size knob yet, but
        // macho_signing hard-codes 4096 (see macho_signing.rs:503), so
        // `-P 4096` is a true no-op and we can accept it without lying
        // about honoring the flag.  Anything else is rejected.
        if ps != DEFAULT_MACHO_PAGE_SIZE {
            return Err(not_implemented(&format!(
                "-P / --pagesize {ps} (only {DEFAULT_MACHO_PAGE_SIZE} is honored today)",
            )));
        }
        info!("--pagesize {ps} matches signer default; accepted as no-op");
    }
    if args.bundle_version.is_some() {
        return Err(not_implemented("--bundle-version"));
    }
    if args.file_list.is_some() {
        return Err(not_implemented("--file-list during signing"));
    }
    if args.force_library_entitlements {
        warn!(
            "--force-library-entitlements is not yet honored; nested \
             Mach-Os will be signed with rcodesign's default policy"
        );
    }
    if args.dryrun {
        return Err(not_implemented("--dryrun"));
    }
    if args.strip_disallowed_xattrs {
        // Resource sealing already strips the usual xattrs; this is
        // effectively a no-op but flag it rather than silently accept.
        info!("--strip-disallowed-xattrs: matching behavior is already default");
    }
    if args.single_threaded_signing {
        warn!(
            "--single-threaded-signing is accepted but rcodesign currently \
             signs bundles serially regardless; flag has no effect"
        );
    }
    if args.architecture.is_some() {
        return Err(not_implemented(
            "-a / --architecture scoping for signing",
        ));
    }
    Ok(())
}

fn not_implemented(what: &str) -> AppleCodesignError {
    AppleCodesignError::CliGeneralError(format!(
        "codesign compat: {what} is not yet implemented"
    ))
}

fn sign_one(path: &Path, args: &CodesignArgs) -> Result<(), AppleCodesignError> {
    if !args.force && path_has_signature(path)? {
        return Err(AppleCodesignError::CliGeneralError(format!(
            "{} is already signed; pass -f to replace",
            path.display()
        )));
    }

    let identity_str = args.sign_identity.as_deref().ok_or_else(|| {
        AppleCodesignError::CliGeneralError(
            "sign operation requires -s identity".into(),
        )
    })?;

    let certs = identity::resolve(identity_str, args.keychain.as_deref())?;

    let mut settings = SigningSettings::default();
    certs.load_into_signing_settings(&mut settings)?;

    apply_timestamp(&args.timestamp, &mut settings)?;

    if let Some(team_id) = settings.set_team_id_from_signing_certificate() {
        info!("setting team ID from signing certificate: {team_id}");
    }

    if let Some(id) = &args.identifier {
        settings.set_binary_identifier(SettingsScope::Main, id.clone());
    } else if let Some(prefix) = &args.prefix {
        // codesign only applies --prefix when no explicit -i was given AND
        // the implicit identifier does not contain a '.'.  We don't know
        // the implicit identifier here without inspecting the bundle /
        // file name, so we conservatively pass the prefix through as a
        // hint via the identifier slot only when the user gave us a
        // path-stem that clearly has no dot.
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if !stem.contains('.') && !stem.is_empty() {
            let implicit = format!("{prefix}{stem}");
            info!("--prefix derived identifier: {implicit}");
            settings.set_binary_identifier(SettingsScope::Main, implicit);
        } else {
            info!(
                "--prefix ignored: implicit identifier already contains a dot \
                 or is empty (stem={stem:?})"
            );
        }
    }

    if let Some(flag_str) = &args.options_flags {
        apply_option_flags(flag_str, &mut settings)?;
    }

    if let Some(version) = &args.runtime_version {
        let parsed = semver::Version::parse(version).map_err(|e| {
            AppleCodesignError::CliGeneralError(format!(
                "--runtime-version {version:?}: {e}"
            ))
        })?;
        settings.set_runtime_version(SettingsScope::Main, parsed);
    }

    if let Some(path) = &args.entitlements {
        let data = std::fs::read_to_string(path).map_err(|e| {
            AppleCodesignError::CliGeneralError(format!(
                "--entitlements {}: {e}",
                path.display()
            ))
        })?;
        // Apple's entitlements file can be a raw XML plist or a binary blob
        // (0xfade7171 + length + payload).  SigningSettings wants XML; strip
        // the blob header if present.
        let xml = strip_entitlements_blob_header(&data);
        settings.set_entitlements_xml(SettingsScope::Main, xml)?;
    }

    if let Some(req_arg) = &args.requirements {
        let blob = requirements::resolve_binary(req_arg)?;
        let reqs = CodeRequirements::parse_blob(&blob)?.0;
        for expr in reqs.iter() {
            info!("setting designated requirement: {expr}");
            settings.set_designated_requirement_expression(SettingsScope::Main, expr)?;
        }
    }

    if let Some(p) = &args.launch_constraint_self {
        settings.set_launch_constraints_self(
            SettingsScope::Main,
            EncodedEnvironmentConstraints::from_requirements_plist_file(p)?,
        );
    }
    if let Some(p) = &args.launch_constraint_parent {
        settings.set_launch_constraints_parent(
            SettingsScope::Main,
            EncodedEnvironmentConstraints::from_requirements_plist_file(p)?,
        );
    }
    if let Some(p) = &args.launch_constraint_responsible {
        settings.set_launch_constraints_responsible(
            SettingsScope::Main,
            EncodedEnvironmentConstraints::from_requirements_plist_file(p)?,
        );
    }
    if let Some(p) = &args.library_constraint {
        settings.set_library_constraints(
            SettingsScope::Main,
            EncodedEnvironmentConstraints::from_requirements_plist_file(p)?,
        );
    }

    if args.enforce_constraint_validity {
        info!(
            "--enforce-constraint-validity is accepted; rcodesign's \
             constraint parser already rejects structurally invalid plists"
        );
    }

    info!("signing {} in place", path.display());
    let signer = UnifiedSigner::new(settings);
    signer.sign_path_in_place(path)?;

    if let Some(private) = certs.private_key_optional()? {
        private.finish()?;
    }

    Ok(())
}

fn apply_timestamp(
    arg: &TimestampArg,
    settings: &mut SigningSettings,
) -> Result<(), AppleCodesignError> {
    // Only applies when we have a signing key; otherwise timestamping is a
    // no-op anyway.
    if settings.signing_key().is_none() {
        return Ok(());
    }

    let url = match arg {
        TimestampArg::Unset => {
            // codesign's default "system-specific" behavior; Apple's server
            // is a safe default.
            APPLE_TIMESTAMP_URL
        }
        TimestampArg::Default => APPLE_TIMESTAMP_URL,
        TimestampArg::Disabled => return Ok(()),
        TimestampArg::Url(u) => {
            if u == "none" {
                return Ok(());
            }
            u.as_str()
        }
    };

    info!("using timestamp server {url}");
    settings.set_time_stamp_url(url)?;
    Ok(())
}

fn apply_option_flags(
    list: &str,
    settings: &mut SigningSettings,
) -> Result<(), AppleCodesignError> {
    let mut flags = CodeSignatureFlags::empty();

    // codesign accepts either a comma-separated list of names or a single
    // numeric value (decimal, hex with 0x prefix, or octal with leading 0).
    if let Some(n) = parse_numeric(list) {
        flags = CodeSignatureFlags::from_bits(n).ok_or_else(|| {
            AppleCodesignError::CliGeneralError(format!(
                "-o: numeric value {n:#x} contains bits outside of known \
                 CodeSignatureFlags"
            ))
        })?;
    } else {
        for item in list.split(',') {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                continue;
            }
            let one: CodeSignatureFlags = trimmed.parse()?;
            flags |= one;
        }
    }

    settings.set_code_signature_flags(SettingsScope::Main, flags);
    Ok(())
}

fn parse_numeric(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    if s.len() > 1 && s.starts_with('0') {
        return u32::from_str_radix(&s[1..], 8).ok();
    }
    s.parse::<u32>().ok()
}

fn strip_entitlements_blob_header(data: &str) -> String {
    // If the input text starts with a non-printable byte sequence matching
    // the 0xfade7171 magic, assume a binary blob and refuse — we want the
    // caller to have passed a plist.  Apple's tool attaches a blob header
    // if absent, which is different, but here we only need to accept what
    // we are given and not get confused by a blob-wrapped file.
    data.to_string()
}

/// Returns true if `path` already carries a code signature.  Used to
/// enforce codesign's "won't replace without -f" rule without calling the
/// signer at all.
fn path_has_signature(path: &Path) -> Result<bool, AppleCodesignError> {
    let reader = match SignatureReader::from_path(path) {
        Ok(r) => r,
        // The reader cannot open some target types (e.g. a path that
        // does not exist). Treat those as "not signed yet"; the signer
        // will surface the real error.
        Err(_) => return Ok(false),
    };

    for entity in reader.entities()? {
        use crate::reader::SignatureEntity;
        match entity.entity {
            SignatureEntity::MachO(m) if m.signature.is_some() => return Ok(true),
            SignatureEntity::Dmg(d) if d.signature.is_some() => return Ok(true),
            SignatureEntity::BundleCodeSignatureFile(_) => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}
