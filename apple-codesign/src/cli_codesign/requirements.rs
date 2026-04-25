// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `-r` / `-R` requirement argument resolution.

use crate::{cli_codesign::options::RequirementArg, error::AppleCodesignError};

/// Resolve the argument into a binary code-requirement blob.
///
/// Real logic is implemented in a later commit.
pub fn resolve_binary(_arg: &RequirementArg) -> Result<Vec<u8>, AppleCodesignError> {
    Err(AppleCodesignError::CliGeneralError(
        "requirement argument resolution is not yet implemented".into(),
    ))
}
