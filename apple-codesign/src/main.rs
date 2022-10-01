// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[allow(unused)]
mod app_store_connect;
#[allow(unused)]
mod apple_certificates;
#[allow(unused)]
mod bundle_signing;
#[allow(unused)]
mod certificate;
#[allow(unused)]
mod cli;
#[allow(unused)]
mod code_directory;
#[allow(unused)]
mod code_requirement;
#[allow(unused)]
mod code_resources;
#[allow(unused)]
mod cryptography;
#[allow(unused)]
mod dmg;
#[allow(unused)]
mod embedded_signature;
#[allow(unused)]
mod embedded_signature_builder;
#[allow(unused)]
mod entitlements;
mod error;
pub use error::*;
#[allow(unused)]
mod macho;
#[allow(unused)]
mod macho_signing;
#[allow(unused)]
mod macho_universal;
#[allow(non_upper_case_globals, unused)]
#[cfg(target_os = "macos")]
mod macos;
mod notarization;
#[allow(unused)]
mod policy;
mod reader;
mod remote_signing;
mod signing;
#[allow(unused)]
mod signing_settings;
pub use signing_settings::*;
#[allow(unused)]
mod specification;
#[allow(unused)]
mod stapling;
#[allow(unused)]
mod ticket_lookup;
#[allow(unused)]
mod verify;
#[cfg(feature = "yubikey")]
#[allow(unused)]
mod yubikey;

fn main() {
    let exit_code = match cli::main_impl() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Error: {}", err);
            1
        }
    };

    std::process::exit(exit_code)
}
