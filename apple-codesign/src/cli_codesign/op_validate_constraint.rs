// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{
        cli_codesign::options::{CodesignArgs, Target},
        environment_constraints::EncodedEnvironmentConstraints,
        error::AppleCodesignError,
    },
    log::info,
};

pub fn run(args: &CodesignArgs) -> Result<(), AppleCodesignError> {
    if args.targets.is_empty() {
        return Err(AppleCodesignError::CliGeneralError(
            "--validate-constraint requires at least one path argument".into(),
        ));
    }

    let mut worst: Option<AppleCodesignError> = None;

    for target in &args.targets {
        let path = match target {
            Target::Path(p) => p,
            Target::Pid(_) | Target::PlusPid(_) => {
                return Err(AppleCodesignError::CliGeneralError(
                    "--validate-constraint only accepts filesystem paths, not PIDs".into(),
                ));
            }
        };

        match EncodedEnvironmentConstraints::from_requirements_plist_file(path) {
            Ok(_) => {
                info!("{}: constraint plist is valid", path.display());
            }
            Err(e) => {
                if args.continue_on_error {
                    eprintln!("{}: {}", path.display(), e);
                    worst.get_or_insert(e);
                } else {
                    return Err(e);
                }
            }
        }
    }

    match worst {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
