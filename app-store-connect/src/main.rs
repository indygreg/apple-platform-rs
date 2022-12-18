use anyhow::Result;
use app_store_connect::bundle_api::{BundleId, BundleIdPlatform};
use app_store_connect::certs_api::{self, Certificate, CertificateType};
use app_store_connect::device_api::Device;
use app_store_connect::profile_api::{Profile, ProfileType};
use app_store_connect::{AppStoreConnectClient, UnifiedApiKey};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    args.command.run()
}

#[derive(Subcommand)]
enum Commands {
    /// Generates a PEM encoded RSA2048 signing key
    GenerateKey {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Certificate type can be one of development, distribution or notarization.
        #[clap(long)]
        r#type: String,
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
        /// Path to write a unified api key.
        api_key: PathBuf,
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
    fn run(self) -> Result<()> {
        match self {
            Self::GenerateKey {
                api_key,
                r#type,
                pem,
            } => {
                let r#type = parse_certificate_type(&r#type)?;
                certs_api::generate_key(&api_key, r#type, &pem)?;
            }
            Self::CreateApiKey {
                issuer_id,
                key_id,
                private_key,
                api_key,
            } => {
                UnifiedApiKey::from_ecdsa_pem_path(issuer_id, key_id, private_key)?
                    .write_json_file(api_key)?;
            }
            Self::Bundle { command } => command.run()?,
            Self::Certificate { command } => command.run()?,
            Self::Device { command } => command.run()?,
            Self::Profile { command } => command.run()?,
        }
        Ok(())
    }
}

#[derive(Subcommand)]
enum BundleCommand {
    Register {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Bundle identifier.
        #[clap(long)]
        identifier: String,
        /// Bundle name.
        #[clap(long)]
        name: String,
    },
    List {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
    },
    Get {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Id of certificate.
        id: String,
    },
    Delete {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Id of bundle id to revoke.
        id: String,
    },
}

impl BundleCommand {
    fn run(self) -> Result<()> {
        match self {
            Self::Register {
                api_key,
                identifier,
                name,
            } => {
                let resp = AppStoreConnectClient::from_json_path(&api_key)?
                    .register_bundle_id(&identifier, &name)?;
                print_bundle_id_header();
                print_bundle_id(&resp.data);
            }
            Self::List { api_key } => {
                let resp = AppStoreConnectClient::from_json_path(&api_key)?.list_bundle_ids()?;
                print_bundle_id_header();
                for bundle_id in &resp.data {
                    print_bundle_id(bundle_id);
                }
            }
            Self::Get { api_key, id } => {
                let resp = AppStoreConnectClient::from_json_path(&api_key)?.get_bundle_id(&id)?;
                print_bundle_id_header();
                print_bundle_id(&resp.data);
            }
            Self::Delete { api_key, id } => {
                AppStoreConnectClient::from_json_path(&api_key)?.delete_bundle_id(&id)?;
            }
        }
        Ok(())
    }
}

fn parse_bundle_id_platform(s: &str) -> Result<BundleIdPlatform> {
    Ok(match s {
        "ios" => BundleIdPlatform::Ios,
        "macos" => BundleIdPlatform::MacOs,
        _ => anyhow::bail!("unsupported bundle id platform {}", s),
    })
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
enum CertificateCommand {
    Create {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Certificate type can be one of development, distribution or notarization.
        #[clap(long)]
        r#type: String,
        /// Path to certificate signing request.
        csr: PathBuf,
    },
    List {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
    },
    Get {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Id of certificate.
        id: String,
    },
    Revoke {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Id of certificate to revoke.
        id: String,
    },
}

impl CertificateCommand {
    fn run(self) -> Result<()> {
        match self {
            Self::Create {
                api_key,
                csr,
                r#type,
            } => {
                let r#type = parse_certificate_type(&r#type)?;
                let csr = std::fs::read_to_string(csr)?;
                let resp = AppStoreConnectClient::from_json_path(&api_key)?
                    .create_certificate(csr, r#type)?;
                print_certificate_header();
                print_certificate(&resp.data);
            }
            Self::List { api_key } => {
                let resp = AppStoreConnectClient::from_json_path(&api_key)?.list_certificates()?;
                print_certificate_header();
                for cert in &resp.data {
                    print_certificate(cert);
                }
            }
            Self::Get { api_key, id } => {
                let resp = AppStoreConnectClient::from_json_path(&api_key)?.get_certificate(&id)?;
                let cer = pem::encode(&pem::Pem {
                    tag: "CERTIFICATE".into(),
                    contents: base64::decode(&resp.data.attributes.certificate_content)?,
                });
                println!("{}", cer);
            }
            Self::Revoke { api_key, id } => {
                AppStoreConnectClient::from_json_path(&api_key)?.revoke_certificate(&id)?;
            }
        }
        Ok(())
    }
}

fn parse_certificate_type(s: &str) -> Result<CertificateType> {
    Ok(match s {
        "development" => CertificateType::Development,
        "distribution" => CertificateType::Distribution,
        "notarization" => CertificateType::DeveloperIdApplication,
        _ => anyhow::bail!("unsupported certificate type {}", s),
    })
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
enum DeviceCommand {
    Register {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Name for device.
        #[clap(long)]
        name: String,
        /// Platform.
        #[clap(long)]
        platform: String,
        /// Unique Device Identifier
        #[clap(long)]
        udid: String,
    },
    List {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
    },
    Get {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Id of device.
        id: String,
    },
}

impl DeviceCommand {
    fn run(self) -> Result<()> {
        match self {
            Self::Register {
                api_key,
                name,
                platform,
                udid,
            } => {
                let platform = parse_bundle_id_platform(&platform)?;
                let resp = AppStoreConnectClient::from_json_path(&api_key)?
                    .register_device(&name, platform, &udid)?;
                print_device_header();
                print_device(&resp.data);
            }
            Self::List { api_key } => {
                let resp = AppStoreConnectClient::from_json_path(&api_key)?.list_devices()?;
                print_device_header();
                for device in &resp.data {
                    print_device(device);
                }
            }
            Self::Get { api_key, id } => {
                let resp = AppStoreConnectClient::from_json_path(&api_key)?.get_device(&id)?;
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
enum ProfileCommand {
    Create {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Name for profile.
        #[clap(long)]
        name: String,
        /// Profile type.
        #[clap(long)]
        profile_type: String,
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
    List {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
    },
    Get {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Id of device.
        id: String,
    },
    Delete {
        /// Path to unified api key.
        #[clap(long)]
        api_key: PathBuf,
        /// Id of device.
        id: String,
    },
}

impl ProfileCommand {
    fn run(self) -> Result<()> {
        match self {
            Self::Create {
                api_key,
                name,
                profile_type,
                bundle_id,
                certificate,
                device,
            } => {
                let profile_type = parse_profile_type(&profile_type)?;
                let resp = AppStoreConnectClient::from_json_path(&api_key)?.create_profile(
                    &name,
                    profile_type,
                    &bundle_id,
                    &certificate,
                    device.as_deref(),
                )?;
                print_profile_header();
                print_profile(&resp.data);
            }
            Self::List { api_key } => {
                let resp = AppStoreConnectClient::from_json_path(&api_key)?.list_profiles()?;
                print_profile_header();
                for profile in &resp.data {
                    print_profile(profile);
                }
            }
            Self::Get { api_key, id } => {
                let resp = AppStoreConnectClient::from_json_path(&api_key)?.get_profile(&id)?;
                let profile = base64::decode(&resp.data.attributes.profile_content)?;
                std::io::stdout().write_all(&profile)?;
            }
            Self::Delete { api_key, id } => {
                AppStoreConnectClient::from_json_path(&api_key)?.delete_profile(&id)?;
            }
        }
        Ok(())
    }
}

fn parse_profile_type(s: &str) -> Result<ProfileType> {
    Ok(match s {
        "ios-dev" => ProfileType::IosAppDevelopment,
        "macos-dev" => ProfileType::MacAppDevelopment,
        "ios-appstore" => ProfileType::IosAppStore,
        "macos-appstore" => ProfileType::MacAppStore,
        "notarization" => ProfileType::MacAppDirect,
        _ => anyhow::bail!("unsupported profile type {}", s),
    })
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
