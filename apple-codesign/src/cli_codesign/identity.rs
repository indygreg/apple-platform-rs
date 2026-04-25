// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `-s identity` / `--keychain` resolution into a [`CertificateSource`].

use crate::{cli::certificate_source::CertificateSource, error::AppleCodesignError};

/// Produce a [`CertificateSource`] from the codesign-style identity string.
///
/// Real logic is implemented in a later commit; this stub only makes the
/// module compile.
pub fn resolve(
    _identity: &str,
    _keychain: Option<&std::path::Path>,
) -> Result<CertificateSource, AppleCodesignError> {
    Err(AppleCodesignError::CliGeneralError(
        "-s identity resolution is not yet implemented".into(),
    ))
}
