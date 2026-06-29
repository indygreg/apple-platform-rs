// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Parsed representation of a `codesign`-style invocation.

use std::path::PathBuf;

/// The single high-level action selected by the argv.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// `-s identity` or `--remove-signature`.
    Sign,
    /// `-v` / `--verify`.
    Verify,
    /// `-d` / `--display`.
    Display,
    /// `-h` / `--hosting`.
    Hosting,
    /// `--validate-constraint`.
    ValidateConstraint,
}

/// A positional argument. `codesign` accepts paths, bare PIDs (decimal leading
/// digit) and `+pid` forms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Target {
    Path(PathBuf),
    Pid(u32),
    PlusPid(u32),
}

/// Form of a `-r` / `-R` argument value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequirementArg {
    /// Plain path to a file (binary blob or text source).
    Path(PathBuf),
    /// `-` — read source from stdin.
    Stdin,
    /// `=source` — source text following the equals sign.
    Source(String),
}

/// Parsed `--preserve-metadata=…` list. Values not explicitly enumerated here
/// are parsed but produce a warning from the sign path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PreserveMetadata {
    pub identifier: bool,
    pub entitlements: bool,
    pub requirements: bool,
    pub flags: bool,
    pub runtime: bool,
    pub launch_constraints: bool,
    pub library_constraints: bool,
    /// The legacy "no value" form — preserves everything known at parse time.
    pub all: bool,
}

/// Parsed `--strict[=opts]` list.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StrictOptions {
    pub symlinks: bool,
    pub sideband: bool,
    /// `--strict` or `--strict=all`.
    pub all: bool,
}

/// Timestamp authority selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimestampArg {
    /// Flag was not supplied.
    Unset,
    /// `--timestamp` with no value — use Apple's default server.
    Default,
    /// `--timestamp=none` — disable timestamping.
    Disabled,
    /// `--timestamp=URL`.
    Url(String),
}

impl Default for TimestampArg {
    fn default() -> Self {
        TimestampArg::Unset
    }
}

/// Fully parsed codesign-compatible invocation.
#[derive(Clone, Debug, Default)]
pub struct CodesignArgs {
    pub operation: Operation,

    // Operation-selector-adjacent fields ------------------------------------
    /// `-s identity`. `None` for verify/display/etc; `Some("-")` for ad-hoc.
    pub sign_identity: Option<String>,
    /// `--remove-signature`.
    pub remove_signature: bool,

    // Generic/shared modifiers ----------------------------------------------
    pub verbose: u8,
    pub force: bool,
    pub continue_on_error: bool,
    pub dryrun: bool,

    // Path/arch selection ---------------------------------------------------
    pub all_architectures: bool,
    pub architecture: Option<String>,
    pub bundle_version: Option<String>,

    // Signing inputs --------------------------------------------------------
    pub identifier: Option<String>,
    pub prefix: Option<String>,
    pub options_flags: Option<String>,
    pub requirements: Option<RequirementArg>,
    pub entitlements: Option<PathBuf>,
    pub generate_entitlement_der: bool,
    pub force_library_entitlements: bool,
    pub keychain: Option<PathBuf>,
    pub page_size: Option<u64>,
    pub runtime_version: Option<String>,
    pub launch_constraint_self: Option<PathBuf>,
    pub launch_constraint_parent: Option<PathBuf>,
    pub launch_constraint_responsible: Option<PathBuf>,
    pub library_constraint: Option<PathBuf>,
    pub enforce_constraint_validity: bool,
    pub strip_disallowed_xattrs: bool,
    pub single_threaded_signing: bool,
    pub detached: Option<PathBuf>,
    pub detached_database: bool,
    pub timestamp: TimestampArg,
    pub preserve_metadata: Option<PreserveMetadata>,
    pub deep: bool,

    // Verify inputs ---------------------------------------------------------
    pub test_requirement: Option<RequirementArg>,
    pub check_notarization: bool,
    pub strict: Option<StrictOptions>,
    pub ignore_resources: bool,

    // Display inputs --------------------------------------------------------
    /// `--entitlements` during display — the target path for extracted data.
    pub display_entitlements: Option<PathBuf>,
    pub display_xml: bool,
    pub display_der: bool,
    pub extract_certificates: Option<String>,
    pub file_list: Option<PathBuf>,

    // Positional targets ----------------------------------------------------
    pub targets: Vec<Target>,
}

impl Default for Operation {
    fn default() -> Self {
        // Chosen so that `Default::default()` on `CodesignArgs` produces a
        // recognizable placeholder; the real operation is always overwritten
        // by the parser.
        Operation::Display
    }
}
