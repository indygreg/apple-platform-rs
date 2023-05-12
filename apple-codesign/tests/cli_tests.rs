// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[test]
fn cli_tests() {
    let cases = trycmd::TestCases::new();
    cases.case("tests/cmd/*.trycmd").case("tests/cmd/*.toml");

    // Help output breaks without notarize feature.
    if cfg!(not(feature = "notarize")) {
        cases.skip("tests/cmd/help.trycmd");
    }
}
