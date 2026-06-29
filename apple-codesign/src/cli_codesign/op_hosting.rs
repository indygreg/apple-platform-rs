// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{cli_codesign::options::CodesignArgs, error::AppleCodesignError};

pub fn run(_args: &CodesignArgs) -> Result<(), AppleCodesignError> {
    Err(AppleCodesignError::CliGeneralError(
        "codesign -h: hosting-chain construction requires libsecurity and \
         is not supported by this build"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosting_is_not_implemented() {
        let mut args = CodesignArgs::default();
        args.operation = crate::cli_codesign::options::Operation::Hosting;
        let err = run(&args).expect_err("hosting must error");
        assert!(format!("{err}").contains("hosting-chain"));
    }
}
