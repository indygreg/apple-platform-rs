// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    std::path::Path,
    trycmd::{schema::TryCmd, Error},
};

fn load_trycmd(path: &Path) -> Result<TryCmd, Error> {
    let mut cmd = TryCmd::load_trycmd(path)?;

    // CWD should be the crate root.
    let cwd = std::env::current_dir().map_err(Error::new)?;

    // We set the test to execute from a sandboxed copy of the crate root.
    // This allows tests to create their own files without disturbing the
    // source checkout.
    cmd.fs.base = Some(cwd.clone());
    cmd.fs.cwd = Some(cwd.clone());
    cmd.fs.sandbox = Some(true);

    Ok(cmd)
}

#[test]
fn cli_tests() {
    let cases = trycmd::TestCases::new();

    cases.file_extension_loader("trycmd", load_trycmd);

    cases.case("tests/cmd/*.trycmd").case("tests/cmd/*.toml");

    // Help output breaks without notarize feature.
    if cfg!(not(feature = "notarize")) {
        cases.skip("tests/cmd/encode-app-store-connect-api-key.trycmd");
        cases.skip("tests/cmd/help.trycmd");
        cases.skip("tests/cmd/notary*.trycmd");
    }
}
