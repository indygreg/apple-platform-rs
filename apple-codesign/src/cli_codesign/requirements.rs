// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `-r` / `-R` requirement argument resolution.
//!
//! `codesign` accepts requirement arguments in four shapes:
//!
//! * a plain path to a file — either a binary blob (magic `0xfade0c00`) or
//!   the textual Code Signing Requirement Language that is compiled on the
//!   fly,
//! * `-` to read requirement source from stdin,
//! * `=source` to inline the source text after the equals sign.
//!
//! rcodesign can only parse the **binary** requirement form today (see
//! `src/lib.rs` — "No parsing of the Code Signing Requirements DSL").  The
//! three remaining shapes therefore return a clear
//! [`AppleCodesignError::CliGeneralError`] so that the caller can produce
//! the requirement blob externally (e.g. `csreq -b`) and feed it back in.

use {
    crate::{
        cli_codesign::options::RequirementArg, code_requirement::CodeRequirements,
        error::AppleCodesignError,
    },
    std::path::Path,
};

/// Resolve a requirement argument into a binary code-requirement blob.
///
/// The returned bytes are in the "requirements blob" form — the same
/// `0xfade0c00`-prefixed data that `csreq -b` emits and that
/// [`CodeRequirements::parse_blob`] accepts.
pub fn resolve_binary(arg: &RequirementArg) -> Result<Vec<u8>, AppleCodesignError> {
    match arg {
        RequirementArg::Path(path) => load_binary_requirement(path),
        RequirementArg::Stdin => Err(AppleCodesignError::CliGeneralError(
            "-r- / -R- (reading requirement source from stdin) is not \
             supported: this build has no text-source Code Signing \
             Requirement compiler; use `csreq -b` to pre-compile and \
             pass the resulting file path"
                .into(),
        )),
        RequirementArg::Source(_) => Err(AppleCodesignError::CliGeneralError(
            "=<source> inline requirement text is not supported: this build \
             has no text-source Code Signing Requirement compiler; use \
             `csreq -b` to pre-compile and pass the resulting file path"
                .into(),
        )),
    }
}

fn load_binary_requirement(path: &Path) -> Result<Vec<u8>, AppleCodesignError> {
    let data = std::fs::read(path)?;

    // Accept both the raw blob form (with the `0xfade0c00` magic) and a
    // "bare requirements set" with no blob wrapper. `SigningSettings` wants
    // the wrapped form; if we are given the bare form, we reject it with a
    // clear error — rcodesign's core only handles the wrapped form.
    CodeRequirements::parse_blob(&data).map_err(|e| {
        AppleCodesignError::CliGeneralError(format!(
            "failed to parse binary requirement from {}: {e}. Is the file \
             the output of `csreq -b`?",
            path.display()
        ))
    })?;

    Ok(data)
}
