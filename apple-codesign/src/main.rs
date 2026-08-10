// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use apple_codesign::AppleCodesignError;

fn main() {
    let exit_code = match dispatch() {
        Ok(()) => 0,
        Err(AppleCodesignError::Figment(err)) => {
            eprintln!("configuration file error");

            err.metadata.as_ref().map(|metadata| {
                metadata.source.as_ref().map(|source| {
                    source.file_path().map(|path| {
                        eprintln!("  source path: {}", path.display());
                    })
                })
            });
            if let Some(profile) = err.profile.as_ref() {
                eprintln!("  in profile: {}", profile)
            }
            eprintln!("  problem key: {}", err.path.join(", "));
            eprintln!("  problem: {:?}", err.kind);

            1
        }
        Err(err) => {
            eprintln!("Error: {err}");
            1
        }
    };

    std::process::exit(exit_code)
}

/// Route between the native `rcodesign` CLI and the `codesign`-compatible one.
///
/// The compat CLI is selected when any of the following are true:
///
/// * `argv[0]`'s basename is `codesign` (e.g. a symlink).
/// * `argv[1]` is the literal string `codesign` (explicit opt-in).
/// * The `RCODESIGN_CODESIGN_COMPAT` environment variable is set to a
///   non-empty value other than `0`.
fn dispatch() -> Result<(), AppleCodesignError> {
    let argv: Vec<String> = std::env::args().collect();

    let program_is_codesign = argv
        .first()
        .map(|arg0| {
            std::path::Path::new(arg0)
                .file_name()
                .and_then(|s| s.to_str())
                .map(|name| name == "codesign")
                .unwrap_or(false)
        })
        .unwrap_or(false);

    let env_forces_compat = std::env::var("RCODESIGN_CODESIGN_COMPAT")
        .ok()
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);

    let second_is_codesign = argv.get(1).map(|s| s.as_str()) == Some("codesign");

    if program_is_codesign || env_forces_compat {
        let rest = argv.into_iter().skip(1).collect();
        apple_codesign::cli_codesign::main_impl(rest)
    } else if second_is_codesign {
        let rest = argv.into_iter().skip(2).collect();
        apple_codesign::cli_codesign::main_impl(rest)
    } else {
        apple_codesign::cli::main_impl()
    }
}
