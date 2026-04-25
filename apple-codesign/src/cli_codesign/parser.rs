// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Argv parser for the codesign-compatible frontend.
//!
//! `codesign(1)` mixes single-character option clusters, GNU long options,
//! options with optional values, and positional path|pid arguments.  This
//! module is a hand-rolled parser because clap's derive API cannot express
//! several of those rules (notably `-v` changing meaning depending on
//! whether an operation flag was seen, and `--name value` being invalid for
//! options with optional values).

use {
    crate::{
        cli_codesign::options::{
            CodesignArgs, Operation, PreserveMetadata, RequirementArg, StrictOptions, Target,
            TimestampArg,
        },
        error::AppleCodesignError,
    },
    std::path::PathBuf,
};

/// Parse a `codesign`-style argv into a [`CodesignArgs`].
pub fn parse(argv: &[String]) -> Result<CodesignArgs, AppleCodesignError> {
    let mut state = State::new();
    let mut i = 0;

    while i < argv.len() {
        let arg = &argv[i];
        i += 1;

        if arg == "--" {
            // Treat everything after as positional.
            while i < argv.len() {
                state.push_target(&argv[i])?;
                i += 1;
            }
            break;
        }

        if let Some(rest) = arg.strip_prefix("--") {
            // Long option: --name or --name=value.
            let (name, inline_value) = match rest.find('=') {
                Some(idx) => (&rest[..idx], Some(rest[idx + 1..].to_string())),
                None => (rest, None),
            };
            handle_long(name, inline_value, argv, &mut i, &mut state)?;
        } else if arg.len() >= 2 && arg.starts_with('-') && !is_pid_like(arg) {
            // Short option cluster.  `-1234` looks like `-` + short cluster,
            // but would parse to meaningless flags; we keep the man-page rule
            // that paths starting with `-` are not accepted (use `--`).
            let cluster = &arg[1..];
            handle_short_cluster(cluster, argv, &mut i, &mut state)?;
        } else {
            state.push_target(arg)?;
        }
    }

    state.finish()
}

fn is_pid_like(arg: &str) -> bool {
    // `+1234` is always a PID-style target.  Bare digits like `1234` are
    // positional paths-or-pids and never short options.  Short clusters always
    // start with a letter in `codesign`.
    if let Some(rest) = arg.strip_prefix('+') {
        return !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit());
    }
    false
}

/// Accumulator for the parser.
struct State {
    args: CodesignArgs,
    /// Tracks whether `-v` has been consumed so we can implement its dual
    /// role: the first `-v` before any operation flag becomes `--verify`;
    /// subsequent `-v` bumps verbosity.
    first_v_consumed: bool,
}

impl State {
    fn new() -> Self {
        Self {
            args: CodesignArgs::default(),
            first_v_consumed: false,
        }
    }

    fn set_operation(&mut self, op: Operation) -> Result<(), AppleCodesignError> {
        // The parser accepts re-specifying the same operation (idempotent) but
        // rejects conflicting ones.
        let explicit = matches!(
            op,
            Operation::Sign
                | Operation::Verify
                | Operation::Display
                | Operation::Hosting
                | Operation::ValidateConstraint
        );
        if explicit && self.operation_is_set() && self.args.operation != op {
            return Err(AppleCodesignError::CliGeneralError(format!(
                "conflicting operation flags: already using {:?}, cannot switch to {:?}",
                self.args.operation, op
            )));
        }
        self.args.operation = op;
        self.first_v_consumed = true; // any explicit op suppresses -v promotion
        Ok(())
    }

    fn operation_is_set(&self) -> bool {
        self.first_v_consumed
    }

    fn handle_v(&mut self) {
        if !self.operation_is_set() {
            // First -v becomes --verify and does not bump verbosity.
            self.args.operation = Operation::Verify;
            self.first_v_consumed = true;
        } else {
            self.args.verbose = self.args.verbose.saturating_add(1);
        }
    }

    fn handle_verbose_explicit(&mut self, value: Option<&str>) -> Result<(), AppleCodesignError> {
        // `--verbose` (long) is always a verbosity bump, never a verify promotion.
        match value {
            None => self.args.verbose = self.args.verbose.saturating_add(1),
            Some(v) => {
                let n: u8 = v.parse().map_err(|_| {
                    AppleCodesignError::CliGeneralError(format!(
                        "--verbose expects an integer, got {v:?}"
                    ))
                })?;
                self.args.verbose = n;
            }
        }
        self.first_v_consumed = true;
        Ok(())
    }

    fn push_target(&mut self, raw: &str) -> Result<(), AppleCodesignError> {
        if let Some(rest) = raw.strip_prefix('+') {
            let pid: u32 = rest.parse().map_err(|_| {
                AppleCodesignError::CliGeneralError(format!("invalid pid: {raw}"))
            })?;
            self.args.targets.push(Target::PlusPid(pid));
            return Ok(());
        }
        if !raw.is_empty() && raw.chars().all(|c| c.is_ascii_digit()) {
            let pid: u32 = raw.parse().map_err(|_| {
                AppleCodesignError::CliGeneralError(format!("invalid pid: {raw}"))
            })?;
            self.args.targets.push(Target::Pid(pid));
            return Ok(());
        }
        self.args.targets.push(Target::Path(PathBuf::from(raw)));
        Ok(())
    }

    fn finish(mut self) -> Result<CodesignArgs, AppleCodesignError> {
        // `--remove-signature` implies the Sign operation (it is a signing
        // operation that happens to strip instead of create).
        if self.args.remove_signature && !self.operation_is_set() {
            self.args.operation = Operation::Sign;
            self.first_v_consumed = true;
        }

        if !self.operation_is_set() {
            return Err(AppleCodesignError::CliGeneralError(
                "no operation specified (use -s, -v, -d, -h, or --validate-constraint)"
                    .into(),
            ));
        }

        Ok(self.args)
    }
}

fn handle_short_cluster(
    cluster: &str,
    argv: &[String],
    idx: &mut usize,
    state: &mut State,
) -> Result<(), AppleCodesignError> {
    let bytes = cluster.as_bytes();
    let mut c = 0;
    while c < bytes.len() {
        let ch = bytes[c] as char;
        c += 1;
        match ch {
            // Flag-only short options.
            'f' => state.args.force = true,
            'v' => state.handle_v(),
            'd' => state.set_operation(Operation::Display)?,
            'h' => state.set_operation(Operation::Hosting)?,

            // Short options that take a value. The value is either the rest
            // of the cluster or, if the cluster is exhausted, the next arg.
            's' => {
                let value = consume_short_value("-s", cluster, &mut c, argv, idx)?;
                state.set_operation(Operation::Sign)?;
                state.args.sign_identity = Some(value);
            }
            'i' => {
                let value = consume_short_value("-i", cluster, &mut c, argv, idx)?;
                state.args.identifier = Some(value);
            }
            'o' => {
                let value = consume_short_value("-o", cluster, &mut c, argv, idx)?;
                state.args.options_flags = Some(value);
            }
            'P' => {
                let value = consume_short_value("-P", cluster, &mut c, argv, idx)?;
                let n: u64 = value.parse().map_err(|_| {
                    AppleCodesignError::CliGeneralError(format!(
                        "-P expects an integer page size, got {value:?}"
                    ))
                })?;
                state.args.page_size = Some(n);
            }
            'r' => {
                let value = consume_short_value("-r", cluster, &mut c, argv, idx)?;
                state.args.requirements = Some(parse_requirement_value(&value));
            }
            'R' => {
                let value = consume_short_value("-R", cluster, &mut c, argv, idx)?;
                state.args.test_requirement = Some(parse_requirement_value(&value));
            }
            'a' => {
                let value = consume_short_value("-a", cluster, &mut c, argv, idx)?;
                state.args.architecture = Some(value);
                state.args.all_architectures = false;
            }
            'D' => {
                let value = consume_short_value("-D", cluster, &mut c, argv, idx)?;
                state.args.detached = Some(PathBuf::from(value));
            }
            _ => {
                return Err(AppleCodesignError::CliGeneralError(format!(
                    "unrecognized short option: -{ch}"
                )));
            }
        }
    }
    Ok(())
}

fn consume_short_value(
    label: &str,
    cluster: &str,
    c: &mut usize,
    argv: &[String],
    idx: &mut usize,
) -> Result<String, AppleCodesignError> {
    // Remaining characters in the same argv word — `-sidentity`.
    if *c < cluster.len() {
        let v = cluster[*c..].to_string();
        *c = cluster.len();
        return Ok(v);
    }
    // Next argv word.
    if *idx < argv.len() {
        let v = argv[*idx].clone();
        *idx += 1;
        return Ok(v);
    }
    Err(AppleCodesignError::CliGeneralError(format!(
        "{label} requires a value"
    )))
}

fn parse_requirement_value(s: &str) -> RequirementArg {
    if s == "-" {
        RequirementArg::Stdin
    } else if let Some(rest) = s.strip_prefix('=') {
        RequirementArg::Source(rest.to_string())
    } else {
        RequirementArg::Path(PathBuf::from(s))
    }
}

#[allow(clippy::too_many_lines)]
fn handle_long(
    name: &str,
    inline_value: Option<String>,
    argv: &[String],
    idx: &mut usize,
    state: &mut State,
) -> Result<(), AppleCodesignError> {
    /// Consumes a required value — inline `--name=value` preferred, otherwise
    /// the next argv word.
    fn required(
        name: &str,
        inline: Option<String>,
        argv: &[String],
        idx: &mut usize,
    ) -> Result<String, AppleCodesignError> {
        if let Some(v) = inline {
            return Ok(v);
        }
        if *idx < argv.len() {
            let v = argv[*idx].clone();
            *idx += 1;
            return Ok(v);
        }
        Err(AppleCodesignError::CliGeneralError(format!(
            "--{name} requires a value"
        )))
    }

    match name {
        // Operations.
        "sign" => {
            let v = required(name, inline_value, argv, idx)?;
            state.set_operation(Operation::Sign)?;
            state.args.sign_identity = Some(v);
        }
        "verify" => state.set_operation(Operation::Verify)?,
        "display" => state.set_operation(Operation::Display)?,
        "hosting" => state.set_operation(Operation::Hosting)?,
        "validate-constraint" => state.set_operation(Operation::ValidateConstraint)?,
        "remove-signature" => state.args.remove_signature = true,

        // Booleans.
        "force" => state.args.force = true,
        "continue" => state.args.continue_on_error = true,
        "dryrun" => state.args.dryrun = true,
        "all-architectures" => {
            state.args.all_architectures = true;
            state.args.architecture = None;
        }
        "deep" => state.args.deep = true,
        "generate-entitlement-der" => state.args.generate_entitlement_der = true,
        "force-library-entitlements" => state.args.force_library_entitlements = true,
        "enforce-constraint-validity" => state.args.enforce_constraint_validity = true,
        "strip-disallowed-xattrs" => state.args.strip_disallowed_xattrs = true,
        "single-threaded-signing" => state.args.single_threaded_signing = true,
        "check-notarization" => state.args.check_notarization = true,
        "ignore-resources" => state.args.ignore_resources = true,
        "detached-database" => state.args.detached_database = true,
        "xml" => state.args.display_xml = true,
        "der" => state.args.display_der = true,

        // Verbosity (always explicit).
        "verbose" => state.handle_verbose_explicit(inline_value.as_deref())?,

        // Valued strings.
        "identifier" => state.args.identifier = Some(required(name, inline_value, argv, idx)?),
        "prefix" => state.args.prefix = Some(required(name, inline_value, argv, idx)?),
        "options" => state.args.options_flags = Some(required(name, inline_value, argv, idx)?),
        "runtime-version" => {
            state.args.runtime_version = Some(required(name, inline_value, argv, idx)?)
        }
        "bundle-version" => {
            state.args.bundle_version = Some(required(name, inline_value, argv, idx)?)
        }
        "architecture" => {
            state.args.architecture = Some(required(name, inline_value, argv, idx)?);
            state.args.all_architectures = false;
        }
        "pagesize" => {
            let v = required(name, inline_value, argv, idx)?;
            let n: u64 = v.parse().map_err(|_| {
                AppleCodesignError::CliGeneralError(format!(
                    "--pagesize expects an integer, got {v:?}"
                ))
            })?;
            state.args.page_size = Some(n);
        }

        // Valued paths.
        "entitlements" => {
            // In display mode, --entitlements names an output destination.
            // In sign mode, it names a source.  The parser cannot yet know
            // the mode, so we always stash the path into both slots; the
            // operation implementations pick the one they need.
            let v = required(name, inline_value, argv, idx)?;
            let path = PathBuf::from(&v);
            state.args.entitlements = Some(path.clone());
            state.args.display_entitlements = Some(path);
        }
        "keychain" => {
            state.args.keychain = Some(PathBuf::from(required(name, inline_value, argv, idx)?))
        }
        "detached" => {
            state.args.detached = Some(PathBuf::from(required(name, inline_value, argv, idx)?))
        }
        "launch-constraint-self" => {
            state.args.launch_constraint_self =
                Some(PathBuf::from(required(name, inline_value, argv, idx)?))
        }
        "launch-constraint-parent" => {
            state.args.launch_constraint_parent =
                Some(PathBuf::from(required(name, inline_value, argv, idx)?))
        }
        "launch-constraint-responsible" => {
            state.args.launch_constraint_responsible =
                Some(PathBuf::from(required(name, inline_value, argv, idx)?))
        }
        "library-constraint" => {
            state.args.library_constraint =
                Some(PathBuf::from(required(name, inline_value, argv, idx)?))
        }
        "file-list" => {
            state.args.file_list =
                Some(PathBuf::from(required(name, inline_value, argv, idx)?))
        }
        "extract-certificates" => {
            // Value is optional in the man page ("If prefix is omitted, the
            // default prefix is 'codesign' in the current directory."), but
            // only when supplied via `--extract-certificates=prefix`.  The
            // safer interpretation is to require a value here when a space
            // was used; an empty inline value activates the default.
            let v = inline_value
                .or_else(|| argv.get(*idx).cloned().inspect(|_| *idx += 1))
                .unwrap_or_else(|| "codesign".to_string());
            state.args.extract_certificates = Some(v);
        }

        // Valued with requirement-argument grammar.
        "requirements" => {
            let v = required(name, inline_value, argv, idx)?;
            state.args.requirements = Some(parse_requirement_value(&v));
        }
        "test-requirement" => {
            let v = required(name, inline_value, argv, idx)?;
            state.args.test_requirement = Some(parse_requirement_value(&v));
        }

        // Options with optional values ("--name value" form NOT accepted —
        // man page says so).
        "timestamp" => {
            state.args.timestamp = match inline_value.as_deref() {
                None => TimestampArg::Default,
                Some("none") => TimestampArg::Disabled,
                Some(url) => TimestampArg::Url(url.to_string()),
            };
        }
        "preserve-metadata" => {
            state.args.preserve_metadata =
                Some(parse_preserve_metadata(inline_value.as_deref())?);
        }
        "strict" => {
            state.args.strict = Some(parse_strict(inline_value.as_deref())?);
        }

        // Misc.
        "help" => {
            // Print a short help banner and succeed; behaves like `codesign
            // --help` which prints a short usage summary to stderr.
            eprintln!("{}", short_help());
            std::process::exit(0);
        }
        "version" => {
            println!("rcodesign {} (codesign-compatible)", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }

        other => {
            return Err(AppleCodesignError::CliGeneralError(format!(
                "unrecognized option: --{other}"
            )));
        }
    }
    Ok(())
}

fn parse_preserve_metadata(value: Option<&str>) -> Result<PreserveMetadata, AppleCodesignError> {
    let mut out = PreserveMetadata::default();
    let Some(v) = value else {
        out.all = true;
        return Ok(out);
    };
    for item in v.split(',') {
        match item.trim() {
            "" => {}
            "identifier" => out.identifier = true,
            "entitlements" => out.entitlements = true,
            "requirements" => out.requirements = true,
            "flags" => out.flags = true,
            "runtime" => out.runtime = true,
            "launch-constraints" => out.launch_constraints = true,
            "library-constraints" => out.library_constraints = true,
            other => {
                return Err(AppleCodesignError::CliGeneralError(format!(
                    "--preserve-metadata: unknown item {other:?}"
                )));
            }
        }
    }
    Ok(out)
}

fn parse_strict(value: Option<&str>) -> Result<StrictOptions, AppleCodesignError> {
    let mut out = StrictOptions::default();
    let Some(v) = value else {
        out.all = true;
        return Ok(out);
    };
    if v == "all" {
        out.all = true;
        return Ok(out);
    }
    for item in v.split(',') {
        match item.trim() {
            "" => {}
            "symlinks" => out.symlinks = true,
            "sideband" => out.sideband = true,
            "all" => out.all = true,
            other => {
                return Err(AppleCodesignError::CliGeneralError(format!(
                    "--strict: unknown item {other:?}"
                )));
            }
        }
    }
    Ok(out)
}

fn short_help() -> &'static str {
    "Usage: codesign -s identity [-fv*] [-o flags] [-r reqs] [-i ident] path ... # sign\n\
     \x20      codesign -v [-v*] [-R=<req string>|-R <req file path>] path|[+]pid ... # verify\n\
     \x20      codesign -d [options] path ... # display contents\n\
     \x20      codesign -h pid ... # display hosting paths\n\
     \x20      codesign --validate-constraint path ... # check the supplied constraint plist"
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> CodesignArgs {
        parse(&parts.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("parse succeeds")
    }

    #[test]
    fn verify_positional() {
        let a = args(&["-v", "/bin/ls"]);
        assert_eq!(a.operation, Operation::Verify);
        assert_eq!(a.verbose, 0);
        assert_eq!(a.targets.len(), 1);
        assert_eq!(a.targets[0], Target::Path(PathBuf::from("/bin/ls")));
    }

    #[test]
    fn verify_then_verbose_counts() {
        // First -v promotes to verify; the next three bump verbosity.
        let a = args(&["-vvvv", "/bin/ls"]);
        assert_eq!(a.operation, Operation::Verify);
        assert_eq!(a.verbose, 3);
    }

    #[test]
    fn sign_with_attached_identity() {
        let a = args(&["-sidentity", "/bin/ls"]);
        assert_eq!(a.operation, Operation::Sign);
        assert_eq!(a.sign_identity.as_deref(), Some("identity"));
    }

    #[test]
    fn sign_with_separate_identity() {
        let a = args(&["-s", "identity", "/bin/ls"]);
        assert_eq!(a.operation, Operation::Sign);
        assert_eq!(a.sign_identity.as_deref(), Some("identity"));
    }

    #[test]
    fn short_cluster_fv() {
        let a = args(&["-fv", "/bin/ls"]);
        assert_eq!(a.operation, Operation::Verify);
        assert!(a.force);
    }

    #[test]
    fn long_sign_and_force() {
        let a = args(&["--sign", "my-id", "-f", "/bin/ls"]);
        assert_eq!(a.operation, Operation::Sign);
        assert!(a.force);
        assert_eq!(a.sign_identity.as_deref(), Some("my-id"));
    }

    #[test]
    fn display_promotes_v_to_verbose() {
        let a = args(&["-d", "-v", "/bin/ls"]);
        assert_eq!(a.operation, Operation::Display);
        assert_eq!(a.verbose, 1);
    }

    #[test]
    fn requirement_forms() {
        let a = args(&["-v", "-R=anchor apple", "/bin/ls"]);
        assert_eq!(
            a.test_requirement,
            Some(RequirementArg::Source("anchor apple".into()))
        );

        let a = args(&["-v", "-R", "/tmp/reqs", "/bin/ls"]);
        assert_eq!(
            a.test_requirement,
            Some(RequirementArg::Path(PathBuf::from("/tmp/reqs")))
        );

        let a = args(&["-v", "-R", "-", "/bin/ls"]);
        assert_eq!(a.test_requirement, Some(RequirementArg::Stdin));
    }

    #[test]
    fn timestamp_forms() {
        let a = args(&["--sign", "x", "--timestamp", "/bin/ls"]);
        assert_eq!(a.timestamp, TimestampArg::Default);
        let a = args(&["--sign", "x", "--timestamp=none", "/bin/ls"]);
        assert_eq!(a.timestamp, TimestampArg::Disabled);
        let a = args(&[
            "--sign",
            "x",
            "--timestamp=http://example.com",
            "/bin/ls",
        ]);
        assert_eq!(
            a.timestamp,
            TimestampArg::Url("http://example.com".into())
        );
    }

    #[test]
    fn preserve_metadata_variants() {
        let a = args(&["--sign", "x", "--preserve-metadata", "/bin/ls"]);
        assert!(a.preserve_metadata.as_ref().unwrap().all);

        let a = args(&[
            "--sign",
            "x",
            "--preserve-metadata=identifier,flags",
            "/bin/ls",
        ]);
        let p = a.preserve_metadata.unwrap();
        assert!(p.identifier);
        assert!(p.flags);
        assert!(!p.all);
    }

    #[test]
    fn strict_variants() {
        let a = args(&["-v", "--strict", "/bin/ls"]);
        assert!(a.strict.as_ref().unwrap().all);

        let a = args(&["-v", "--strict=symlinks,sideband", "/bin/ls"]);
        let s = a.strict.unwrap();
        assert!(s.symlinks);
        assert!(s.sideband);
        assert!(!s.all);
    }

    #[test]
    fn pid_targets() {
        let a = args(&["-v", "123", "+456", "/bin/ls"]);
        assert_eq!(a.targets.len(), 3);
        assert_eq!(a.targets[0], Target::Pid(123));
        assert_eq!(a.targets[1], Target::PlusPid(456));
        assert_eq!(a.targets[2], Target::Path(PathBuf::from("/bin/ls")));
    }

    #[test]
    fn double_dash_terminator() {
        let a = args(&["-v", "--", "--weird-file"]);
        assert_eq!(a.targets.len(), 1);
        assert_eq!(
            a.targets[0],
            Target::Path(PathBuf::from("--weird-file"))
        );
    }

    #[test]
    fn remove_signature_is_sign_op() {
        let a = args(&["--remove-signature", "/bin/ls"]);
        assert_eq!(a.operation, Operation::Sign);
        assert!(a.remove_signature);
    }

    #[test]
    fn conflicting_operations_reject() {
        let err = parse(
            &["-s", "x", "-d", "/bin/ls"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn missing_operation_reject() {
        let err = parse(
            &["/bin/ls"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn architecture_disables_all() {
        let a = args(&["-v", "--all-architectures", "-a", "arm64", "/bin/ls"]);
        assert_eq!(a.architecture.as_deref(), Some("arm64"));
        assert!(!a.all_architectures);
    }

    #[test]
    fn validate_constraint() {
        let a = args(&["--validate-constraint", "/tmp/c.plist"]);
        assert_eq!(a.operation, Operation::ValidateConstraint);
        assert_eq!(
            a.targets[0],
            Target::Path(PathBuf::from("/tmp/c.plist"))
        );
    }
}
