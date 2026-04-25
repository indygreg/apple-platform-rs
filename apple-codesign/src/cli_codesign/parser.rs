// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Argv parser for the codesign-compatible frontend.

use crate::{cli_codesign::options::CodesignArgs, error::AppleCodesignError};

/// Parse a `codesign`-style argv into a [`CodesignArgs`].
pub fn parse(_argv: &[String]) -> Result<CodesignArgs, AppleCodesignError> {
    Err(AppleCodesignError::CliGeneralError(
        "codesign-compatible CLI is not yet implemented".into(),
    ))
}
