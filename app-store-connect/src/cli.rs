// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::bundle_api::{BundleId, BundleIdPlatform};
use crate::certs_api::{self, Certificate, CertificateType};
use crate::device_api::Device;
use crate::profile_api::{Profile, ProfileType};
use crate::{AppStoreConnectClient, UnifiedApiKey};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as STANDARD_ENGINE, Engine};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Path to unified api key.
    #[clap(long, global = true)]
    pub api_key: Option<PathBuf>,
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generates a PEM encoded RSA2048 signing key
    GenerateSigningCertificate {
        /// Certificate type can be one of development, distribution or notarization.
        #[clap(long)]
        r#type: CertificateType,
        /// Path to write a new PEM encoded RSA2048 signing key
        pem: PathBuf,
    },
    /// Creates a unified api key.
    CreateApiKey {
        /// Issuer id.
        #[clap(long)]
        issuer_id: String,
        /// Key id.
        #[clap(long)]
        key_id: String,
        /// Path to private key.
        private_key: PathBuf,
    },
    Bundle {
        #[clap(subcommand)]
        command: BundleCommand,
    },
    Certificate {
        #[clap(subcommand)]
        command: CertificateCommand,
    },
    Device {
        #[clap(subcommand)]
        command: DeviceCommand,
    },
    Profile {
        #[clap(subcommand)]
        command: ProfileCommand,
    },
}

impl Commands {
    pub fn run(self, api_key: &Path) -> Result<()> {
        match self {
            Self::GenerateSigningCertificate { r#type, pem } => {
                certs_api::generate_signing_certificate(api_key, r#type, &pem)?;
            }
            Self::CreateApiKey {
                issuer_id,
                key_id,
                private_key,
            } => {
                UnifiedApiKey::from_ecdsa_pem_path(issuer_id, key_id, private_key)?
                    .write_json_file(api_key)?;
            }
            Self::Bundle { command } => command.run(api_key)?,
            Self::Certificate { command } => command.run(api_key)?,
            Self::Device { command } => command.run(api_key)?,
            Self::Profile { command } => command.run(api_key)?,
        }
        Ok(())
    }
}

#[derive(Subcommand)]
pub enum BundleCommand {
    Register {
        /// Bundle identifier.
        #[clap(long)]
        identifier: String,
        /// Bundle name.
        #[clap(long)]
        name: String,
    },
    List,
    Get {
        /// Id of certificate.
        id: String,
    },
    Delete {
        /// Id of bundle id to revoke.
        id: String,
    },
}

impl BundleCommand {
    pub fn run(self, api_key: &Path) -> Result<()> {
        let client = AppStoreConnectClient::from_json_path(api_key)?;
        match self {
            Self::Register { identifier, name } => {
                let resp = client.register_bundle_id(&identifier, &name)?;
                print_bundle_id_header();
                print_bundle_id(&resp.data);
            }
            Self::List => {
                let resp = client.list_bundle_ids()?;
                print_bundle_id_header();
                for bundle_id in &resp.data {
                    print_bundle_id(bundle_id);
                }
            }
            Self::Get { id } => {
                let resp = client.get_bundle_id(&id)?;
                print_bundle_id_header();
                print_bundle_id(&resp.data);
            }
            Self::Delete { id } => {
                client.delete_bundle_id(&id)?;
            }
        }
        Ok(())
    }
}

fn print_bundle_id_header() {
    println!("{: <10} | {: <20} | {: <30}", "id", "name", "identifier");
}

fn print_bundle_id(bundle_id: &BundleId) {
    println!(
        "{: <10} | {: <20} | {: <30}",
        bundle_id.id, bundle_id.attributes.name, bundle_id.attributes.identifier,
    );
}

#[derive(Subcommand)]
pub enum CertificateCommand {
    Create {
        /// Certificate type can be one of development, distribution or notarization.
        #[clap(long)]
        r#type: CertificateType,
        /// Path to certificate signing request.
        csr: PathBuf,
    },
    List,
    Get {
        /// Id of certificate.
        id: String,
    },
    Revoke {
        /// Id of certificate to revoke.
        id: String,
    },
}

impl CertificateCommand {
    pub fn run(self, api_key: &Path) -> Result<()> {
        let client = AppStoreConnectClient::from_json_path(api_key)?;
        match self {
            Self::Create { csr, r#type } => {
                let csr = std::fs::read_to_string(csr)?;
                let resp = client.create_certificate(csr, r#type)?;
                print_certificate_header();
                print_certificate(&resp.data);
            }
            Self::List => {
                let resp = client.list_certificates()?;
                print_certificate_header();
                for cert in &resp.data {
                    print_certificate(cert);
                }
            }
            Self::Get { id } => {
                let resp = client.get_certificate(&id)?;
                let cer = pem::encode(&pem::Pem::new(
                    "CERTIFICATE",
                    STANDARD_ENGINE.decode(resp.data.attributes.certificate_content)?,
                ));
                println!("{cer}");
            }
            Self::Revoke { id } => {
                client.revoke_certificate(&id)?;
            }
        }
        Ok(())
    }
}

fn print_certificate_header() {
    println!(
        "{: <10} | {: <50} | {: <20}",
        "id", "name", "expiration date"
    );
}

fn print_certificate(cert: &Certificate) {
    let expiration_date = cert.attributes.expiration_date.split_once('T').unwrap().0;
    println!(
        "{: <10} | {: <50} | {: <10}",
        cert.id, cert.attributes.name, expiration_date
    );
}

#[derive(Subcommand)]
pub enum DeviceCommand {
    Register {
        /// Name for device.
        #[clap(long)]
        name: String,
        /// Platform.
        #[clap(long)]
        platform: BundleIdPlatform,
        /// Unique Device Identifier
        #[clap(long)]
        udid: String,
    },
    List,
    Get {
        /// Id of device.
        id: String,
    },
}

impl DeviceCommand {
    pub fn run(self, api_key: &Path) -> Result<()> {
        let client = AppStoreConnectClient::from_json_path(api_key)?;
        match self {
            Self::Register {
                name,
                platform,
                udid,
            } => {
                let resp = client.register_device(&name, platform, &udid)?;
                print_device_header();
                print_device(&resp.data);
            }
            Self::List => {
                let resp = client.list_devices()?;
                print_device_header();
                for device in &resp.data {
                    print_device(device);
                }
            }
            Self::Get { id } => {
                let resp = client.get_device(&id)?;
                print_device_header();
                print_device(&resp.data);
            }
        }
        Ok(())
    }
}

fn print_device_header() {
    println!(
        "{: <10} | {: <20} | {: <20} | {: <20}",
        "id", "name", "model", "udid"
    );
}

fn print_device(device: &Device) {
    let model = device.attributes.model.as_deref().unwrap_or_default();
    println!(
        "{: <10} | {: <20} | {: <20} | {: <20}",
        device.id, device.attributes.name, model, device.attributes.udid,
    );
}

#[derive(Subcommand)]
pub enum ProfileCommand {
    Create {
        /// Name for profile.
        #[clap(long)]
        name: String,
        /// Profile type.
        #[clap(long)]
        profile_type: ProfileType,
        /// Bundle identifier id.
        #[clap(long)]
        bundle_id: String,
        /// Certificate ids.
        #[clap(long)]
        certificate: Vec<String>,
        /// Device ids.
        #[clap(long)]
        device: Option<Vec<String>>,
    },
    List,
    Get {
        /// Id of device.
        id: String,
    },
    Delete {
        /// Id of device.
        id: String,
    },
}

impl ProfileCommand {
    pub fn run(self, api_key: &Path) -> Result<()> {
        let client = AppStoreConnectClient::from_json_path(api_key)?;
        match self {
            Self::Create {
                name,
                profile_type,
                bundle_id,
                certificate,
                device,
            } => {
                let resp = client.create_profile(
                    &name,
                    profile_type,
                    &bundle_id,
                    &certificate,
                    device.as_deref(),
                )?;
                print_profile_header();
                print_profile(&resp.data);
            }
            Self::List => {
                let resp = client.list_profiles()?;
                print_profile_header();
                for profile in &resp.data {
                    print_profile(profile);
                }
            }
            Self::Get { id } => {
                let resp = client.get_profile(&id)?;
                let profile = STANDARD_ENGINE.decode(resp.data.attributes.profile_content)?;
                std::io::stdout().write_all(&profile)?;
            }
            Self::Delete { id } => {
                client.delete_profile(&id)?;
            }
        }
        Ok(())
    }
}

fn print_profile_header() {
    println!(
        "{: <10} | {: <20} | {: <20} | {: <20}",
        "id", "name", "type", "expiration date"
    );
}

fn print_profile(profile: &Profile) {
    let expiration_date = profile
        .attributes
        .expiration_date
        .split_once('T')
        .unwrap()
        .0;
    println!(
        "{: <10} | {: <20} | {: <20} | {: <20}",
        profile.id, profile.attributes.name, profile.attributes.profile_type, expiration_date,
    );
}
