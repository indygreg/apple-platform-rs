// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! End-to-end smoke tests for the codesign-compatible CLI frontend.
//!
//! These exercise the public [`apple_codesign::cli_codesign::main_impl`]
//! entry point — the same path that `main.rs` takes when argv[0] is
//! `codesign` — without spawning a subprocess.  Operations that would
//! depend on a real signed binary on disk are covered by asserting the
//! expected "not supported" / "not implemented" errors.

use apple_codesign::{cli_codesign, AppleCodesignError};

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[test]
fn missing_operation_errors() {
    let err = cli_codesign::main_impl(argv(&["/bin/ls"])).unwrap_err();
    match err {
        AppleCodesignError::CliGeneralError(m) => {
            assert!(m.contains("no operation specified"), "message was: {m}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn hosting_is_not_supported() {
    let err = cli_codesign::main_impl(argv(&["-h", "1"])).unwrap_err();
    match err {
        AppleCodesignError::CliGeneralError(m) => {
            assert!(m.contains("hosting-chain"), "message was: {m}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn verify_pid_returns_not_supported() {
    let err = cli_codesign::main_impl(argv(&["-v", "+1"])).unwrap_err();
    match err {
        AppleCodesignError::CliGeneralError(m) => {
            assert!(m.contains("dynamic validation"), "message was: {m}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn validate_constraint_requires_arg() {
    let err = cli_codesign::main_impl(argv(&["--validate-constraint"])).unwrap_err();
    match err {
        AppleCodesignError::CliGeneralError(m) => {
            assert!(m.contains("at least one path"), "message was: {m}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn sign_pagesize_is_not_implemented() {
    let err = cli_codesign::main_impl(argv(&[
        "-s", "-", "-P", "4096", "/nonexistent/path",
    ]))
    .unwrap_err();
    match err {
        AppleCodesignError::CliGeneralError(m) => {
            assert!(m.contains("pagesize"), "message was: {m}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn sign_detached_is_not_implemented() {
    let err = cli_codesign::main_impl(argv(&[
        "-s", "-", "-D", "/tmp/out.sig", "/nonexistent/path",
    ]))
    .unwrap_err();
    match err {
        AppleCodesignError::CliGeneralError(m) => {
            assert!(m.contains("--detached"), "message was: {m}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn sign_remove_signature_is_not_implemented() {
    let err = cli_codesign::main_impl(argv(&[
        "--remove-signature",
        "/nonexistent/path",
    ]))
    .unwrap_err();
    match err {
        AppleCodesignError::CliGeneralError(m) => {
            assert!(m.contains("--remove-signature"), "message was: {m}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn validate_constraint_rejects_missing_file() {
    // A path that does not exist should produce an I/O error from the
    // constraint parser, not a generic "not implemented" message — this
    // confirms we reached the real primitive.
    let err = cli_codesign::main_impl(argv(&[
        "--validate-constraint",
        "/this/path/does/not/exist.plist",
    ]))
    .unwrap_err();
    // Accept any concrete error; just reject the "not implemented" stub.
    let msg = format!("{err}");
    assert!(
        !msg.contains("not yet implemented"),
        "should have attempted validation, got: {msg}"
    );
}
