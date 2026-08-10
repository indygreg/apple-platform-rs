// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A CLI frontend that accepts the argument grammar of Apple's `codesign(1)`.
//!
//! This module is a translation layer. It re-uses the primitives exposed by
//! the rest of the crate (`UnifiedSigner`, `SigningSettings`,
//! `SignatureReader`, `Stapler`, …) and does **not** change signing
//! semantics. Flags whose behavior would require changes to core signing
//! modules are accepted and produce a clear "not implemented" error.

pub mod options;
pub mod parser;

mod identity;
mod op_display;
mod op_hosting;
mod op_sign;
mod op_validate_constraint;
mod op_verify;
mod requirements;

use {
    crate::{
        cli_codesign::options::{CodesignArgs, Operation},
        error::AppleCodesignError,
    },
    log::LevelFilter,
};

/// Entry point when the binary is invoked with `codesign`-style argv.
///
/// `argv` is the full argument vector **excluding** `argv[0]` — the caller
/// strips the program name (or the leading `codesign` subcommand) before
/// calling us.
pub fn main_impl(argv: Vec<String>) -> Result<(), AppleCodesignError> {
    let args = parser::parse(&argv)?;
    init_logging(args.verbose);
    run(args)
}

fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let mut builder = env_logger::Builder::new();
    builder.filter_level(level).parse_default_env();
    if level <= LevelFilter::Info {
        builder
            .format_timestamp(None)
            .format_level(false)
            .format_target(false);
    }
    // Initializing twice panics; ignore the error so unit tests that exercise
    // `main_impl` repeatedly in the same process still work.
    let _ = builder.try_init();
}

fn run(args: CodesignArgs) -> Result<(), AppleCodesignError> {
    match args.operation {
        Operation::Sign => op_sign::run(&args),
        Operation::Verify => op_verify::run(&args),
        Operation::Display => op_display::run(&args),
        Operation::Hosting => op_hosting::run(&args),
        Operation::ValidateConstraint => op_validate_constraint::run(&args),
    }
}
