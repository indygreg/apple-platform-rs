// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{
        cli::get_pkcs12_password,
        cryptography::{parse_pfx_data, InMemoryPrivateKey, PrivateKey},
        error::AppleCodesignError,
        remote_signing::{
            session_negotiation::{PublicKeyInitiator, SessionInitiatePeer, SharedSecretInitiator},
            RemoteSignError, UnjoinedSigningClient,
        },
        signing_settings::SigningSettings,
    },
    base64::{engine::general_purpose::STANDARD as STANDARD_ENGINE, Engine},
    clap::Args,
    log::{error, info, warn},
    serde::{Deserialize, Serialize},
    spki::EncodePublicKey,
    std::path::PathBuf,
    x509_certificate::CapturedX509Certificate,
    std::convert::TryFrom,
};

#[cfg(feature = "yubikey")]
use {
    crate::{cli::prompt_smartcard_pin, yubikey::YubiKey},
    std::str::FromStr,
};

#[cfg(feature = "pkcs11")]
use {
    crate::pkcs11::Pkcs11PrivateKey,
    cryptoki::{
        context::{CInitializeArgs, Pkcs11},
    },
};

#[cfg(target_os = "macos")]
use crate::macos::{keychain_find_code_signing_certificates, KeychainDomain};

#[cfg(target_os = "windows")]
use crate::windows::{windows_store_find_code_signing_certificates, StoreName};

/// Represents a set of keys and certificates.
#[derive(Default)]

pub struct SigningCertificates {
    pub keys: Vec<Box<dyn PrivateKey>>,
    pub certs: Vec<CapturedX509Certificate>,
}

impl SigningCertificates {
    pub fn extend(&mut self, other: Self) {
        self.keys.extend(other.keys);
        self.certs.extend(other.certs);
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.certs.is_empty()
    }

    /// Resolve a private key in this collection.
    ///
    /// Errors unless the number of keys is exactly one.
    pub fn private_key(&self) -> Result<&dyn PrivateKey, AppleCodesignError> {
        self.private_key_optional()?
            .ok_or_else(|| AppleCodesignError::CliGeneralError("no private key found".into()))
    }

    /// Resolve an optional private key in this collection.
    ///
    /// Errors if there are more than 1 key.
    pub fn private_key_optional(&self) -> Result<Option<&dyn PrivateKey>, AppleCodesignError> {
        match self.keys.len() {
            0 => Ok(None),
            1 => Ok(Some(self.keys[0].as_ref())),
            n => Err(AppleCodesignError::CliGeneralError(format!(
                "at most 1 private keys can be present (found {n})"
            ))),
        }
    }

    /// Loads the instance into a [SigningSettings].
    pub fn load_into_signing_settings<'settings, 'slf: 'settings>(
        &'slf self,
        settings: &'settings mut SigningSettings<'slf>,
    ) -> Result<(), AppleCodesignError> {
        let private = self.private_key_optional()?;

        let mut public_certificates = self.certs.clone();

        if let Some(signing_key) = &private {
            if public_certificates.is_empty() {
                error!("a PRIVATE KEY requires a corresponding CERTIFICATE to pair with it");
                return Err(AppleCodesignError::CliBadArgument);
            }

            let cert = public_certificates.remove(0);

            warn!("registering signing key");

            if !cert.time_constraints_valid(None) {
                warn!(
                    "signing certificate expired as of {}; signatures may not be valid",
                    cert.validity_not_after().to_rfc3339()
                );
            }

            settings.set_signing_key(signing_key.as_key_info_signer(), cert);
            if let Some(certs) = settings.chain_apple_certificates() {
                for cert in certs {
                    warn!(
                        "automatically registered Apple CA certificate: {}",
                        cert.subject_common_name()
                            .unwrap_or_else(|| "default".into())
                    );
                }
            }
        }

        for cert in public_certificates {
            warn!("registering extra X.509 certificate");
            settings.chain_certificate(cert);
        }

        Ok(())
    }
}

pub trait KeySource {
    /// Obtain a bag of private keys and certificates from the instance.
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError>;

    /// Whether key source is the lone/exclusive source of keys + certs.
    fn exclusive(&self) -> bool {
        false
    }
}

#[derive(Args, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmartcardSigningKey {
    /// Smartcard slot number of signing certificate to use (9c is common)
    #[arg(long = "smartcard-slot", value_name = "SLOT")]
    pub slot: Option<String>,

    /// Smartcard PIN used to unlock certificate
    ///
    /// If not provided, you will be prompted for a PIN as necessary.
    #[arg(long = "smartcard-pin", value_name = "SECRET")]
    pub pin: Option<String>,

    /// Environment variable holding the smartcard PIN
    #[arg(long = "smartcard-pin-env", value_name = "STRING")]
    #[serde(skip)]
    pub pin_env: Option<String>,
}

impl KeySource for SmartcardSigningKey {
    #[cfg(feature = "yubikey")]
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        if let Some(slot) = &self.slot {
            let slot_id = ::yubikey::piv::SlotId::from_str(slot)?;
            let formatted = hex::encode([u8::from(slot_id)]);
            let mut yk = YubiKey::new()?;

            if let Some(pin) = &self.pin {
                let pin = pin.clone();
                yk.set_pin_callback(move || Ok(pin.as_bytes().to_vec()));
            } else if let Some(pin_var) = &self.pin_env {
                let pin_var = pin_var.to_owned();

                yk.set_pin_callback(move || {
                    if let Ok(pin) = std::env::var(&pin_var) {
                        eprintln!("using PIN from {} environment variable", &pin_var);
                        Ok(pin.as_bytes().to_vec())
                    } else {
                        prompt_smartcard_pin()
                    }
                });
            } else {
                yk.set_pin_callback(prompt_smartcard_pin);
            }

            if let Some(signer) = yk.get_certificate_signer(slot_id)? {
                warn!("using certificate in smartcard slot {}", formatted);

                let cert = signer.certificate().clone();

                Ok(SigningCertificates {
                    keys: vec![Box::new(signer)],
                    certs: vec![cert],
                })
            } else {
                Err(AppleCodesignError::SmartcardNoCertificate(formatted))
            }
        } else {
            Ok(Default::default())
        }
    }

    #[cfg(not(feature = "yubikey"))]
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        if self.slot.is_some() {
            error!("smartcard support not available; ignoring --smartcard-slot");
        }

        Ok(Default::default())
    }
}

#[derive(Args, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacosKeychainSigningKey {
    /// (macOS only) Keychain domain to operate on
    #[arg(long = "keychain-domain", group = "keychain", value_parser = crate::cli::KEYCHAIN_DOMAINS, value_name = "DOMAIN")]
    #[serde(default)]
    pub domains: Vec<String>,

    /// (macOS only) SHA-256 fingerprint of certificate in Keychain to use
    #[arg(
        long = "keychain-fingerprint",
        group = "keychain",
        value_name = "SHA256 FINGERPRINT"
    )]
    pub sha256_fingerprint: Option<String>,
}

impl KeySource for MacosKeychainSigningKey {
    #[cfg(target_os = "macos")]
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        // No arguments pertinent to keychains. Don't even speak to the
        // keychain API since this could only error.
        if self.domains.is_empty() && self.sha256_fingerprint.is_none() {
            return Ok(Default::default());
        }

        // Collect all the keychain domains to search.
        let domains = if self.domains.is_empty() {
            vec!["user".to_string()]
        } else {
            self.domains.clone()
        };

        let domains = domains
            .into_iter()
            .map(|domain| {
                KeychainDomain::try_from(domain.as_str())
                    .expect("clap should have validated domain values")
            })
            .collect::<Vec<_>>();

        // Now iterate all the keychains and try to find requested certificates.
        let mut res = SigningCertificates::default();

        for domain in domains {
            for cert in keychain_find_code_signing_certificates(domain, None)? {
                let matches = if let Some(wanted_fingerprint) = &self.sha256_fingerprint {
                    let got_fingerprint = hex::encode(cert.sha256_fingerprint()?.as_ref());

                    wanted_fingerprint.eq_ignore_ascii_case(&got_fingerprint)
                } else {
                    false
                };

                if matches {
                    res.certs.push(cert.as_captured_x509_certificate());
                    res.keys.push(Box::new(cert));
                }
            }
        }

        Ok(res)
    }

    #[cfg(not(target_os = "macos"))]
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        if !self.domains.is_empty() || self.sha256_fingerprint.is_some() {
            error!(
                "--keychain* arguments only supported on macOS and will be ignored on this platform"
            );
        }

        Ok(Default::default())
    }
}

#[derive(Args, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsStoreSigningKey {
    /// (Windows only) Windows Store to operate on
    #[arg(long = "windows-store-name", value_parser = crate::cli::WINDOWS_STORE_NAMES, value_name = "STORE")]
    pub stores: Vec<String>,

    /// (Windows only) SHA-1 fingerprint of certificate in Windows Store to use
    #[arg(
        long = "windows-store-sha1-fingerprint",
        value_name = "SHA1 FINGERPRINT"
    )]
    pub sha1_fingerprint: Option<String>,
}

impl KeySource for WindowsStoreSigningKey {
    #[cfg(target_os = "windows")]
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        // No arguments pertinent to store. Don't even speak to the
        // Windows API since this could only error.
        if self.stores.is_empty() && self.sha1_fingerprint.is_none() {
            return Ok(Default::default());
        }

        // Collect all the store names to search.
        let stores = if self.stores.is_empty() {
            vec!["user".to_string()]
        } else {
            self.stores.clone()
        };

        let stores = stores
            .into_iter()
            .map(|store| {
                StoreName::try_from(store.as_str())
                    .expect("clap should have validated store name values")
            })
            .collect::<Vec<_>>();

        // Now iterate all the stores and try to find requested certificates.
        let mut res = SigningCertificates::default();

        for store in stores {
            for cert in windows_store_find_code_signing_certificates(store)? {
                let matches = if let Some(wanted_fingerprint) = &self.sha1_fingerprint {
                    let got_fingerprint = hex::encode(cert.sha1_fingerprint()?.as_ref());

                    wanted_fingerprint.to_ascii_lowercase() == got_fingerprint.to_ascii_lowercase()
                } else {
                    false
                };

                if matches {
                    res.certs.push(cert.as_captured_x509_certificate());
                    res.keys.push(Box::new(cert));
                }
            }
        }

        Ok(res)
    }

    #[cfg(not(target_os = "windows"))]
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        if !self.stores.is_empty() || self.sha1_fingerprint.is_some() {
            error!(
                "--windows-store* arguments only supported on Windows and will be ignored on this platform"
            );
        }

        Ok(Default::default())
    }
}

#[derive(Args, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct P12SigningKey {
    /// Path to a .p12/PFX file containing a certificate key pair
    #[arg(long = "p12-file", alias = "pfx-file", value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// The password to use to open the --p12-file file
    #[arg(
        long = "p12-password",
        alias = "pfx-password",
        group = "p12-password",
        value_name = "SECRET"
    )]
    pub password: Option<String>,

    // TODO conflicts with p12_password
    /// Path to file containing password for opening --p12-file file
    #[arg(
        long = "p12-password-file",
        alias = "pfx-password-file",
        group = "p12-password",
        value_name = "PATH"
    )]
    pub password_path: Option<PathBuf>,
}

impl KeySource for P12SigningKey {
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        if let Some(path) = &self.path {
            let p12_data = std::fs::read(path)?;

            let p12_password =
                get_pkcs12_password(self.password.clone(), self.password_path.clone())?;

            let (cert, key) = parse_pfx_data(&p12_data, &p12_password)?;

            Ok(SigningCertificates {
                keys: vec![Box::new(key)],
                certs: vec![cert],
            })
        } else {
            Ok(Default::default())
        }
    }
}

#[derive(Args, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PemSigningKey {
    /// Path to file containing PEM encoded certificate/key data
    #[arg(long = "pem-file", alias = "pem-source", value_name = "PATH")]
    #[serde(rename = "files")]
    pub paths: Vec<PathBuf>,
}

impl KeySource for PemSigningKey {
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        let mut res = SigningCertificates::default();

        for path in &self.paths {
            warn!("reading PEM data from {}", path.display());
            let pem_data = std::fs::read(path)?;

            for pem in pem::parse_many(pem_data).map_err(AppleCodesignError::CertificatePem)? {
                match pem.tag() {
                    "CERTIFICATE" => {
                        info!("adding certificate from {}", path.display());
                        res.certs
                            .push(CapturedX509Certificate::from_der(pem.contents())?);
                    }
                    "PRIVATE KEY" => {
                        info!("adding private key from {}", path.display());
                        res.keys.push(Box::new(InMemoryPrivateKey::from_pkcs8_der(
                            pem.contents(),
                        )?));
                    }
                    "RSA PRIVATE KEY" => {
                        info!("adding RSA private key from {}", path.display());
                        res.keys.push(Box::new(InMemoryPrivateKey::from_pkcs1_der(
                            pem.contents(),
                        )?));
                    }
                    tag => warn!("(unhandled PEM tag {}; ignoring)", tag),
                }
            }
        }

        Ok(res)
    }
}

#[derive(Args, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSigningKey {
    /// URL of a remote code signing server
    #[arg(long = "remote-signing-url", value_name = "URL")]
    pub url: Option<String>,

    /// Base64 encoded public key data describing the signer
    #[arg(
        long = "remote-public-key",
        group = "remote-initialization",
        value_name = "BASE64 ENCODED PUBLIC KEY"
    )]
    pub public_key: Option<String>,

    /// PEM encoded public key data describing the signer
    #[arg(
        long = "remote-public-key-pem-file",
        group = "remote-initialization",
        group = "remote-initialization",
        value_name = "PATH"
    )]
    pub public_key_pem_path: Option<PathBuf>,

    /// Shared secret used for remote signing
    #[arg(
        long = "remote-shared-secret",
        group = "remote-initialization",
        value_name = "SECRET"
    )]
    pub shared_secret: Option<String>,

    /// Environment variable holding the shared secret used for remote signing
    #[arg(
        long = "remote-shared-secret-env",
        group = "remote-initialization",
        value_name = "ENV VAR NAME"
    )]
    pub shared_secret_env: Option<String>,
}

impl KeySource for RemoteSigningKey {
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        if let Some(initiator) = self.remote_signing_initiator()? {
            let client = UnjoinedSigningClient::new_initiator(
                self.url(),
                initiator,
                Some(super::print_session_join),
            )?;

            let mut certs = vec![client.signing_certificate().clone()];
            certs.extend(client.certificate_chain().iter().cloned());

            Ok(SigningCertificates {
                keys: vec![Box::new(client)],
                certs,
            })
        } else {
            Ok(Default::default())
        }
    }

    fn exclusive(&self) -> bool {
        true
    }
}

impl RemoteSigningKey {
    /// Obtain the URL of the relay server.
    pub fn url(&self) -> String {
        self.url
            .clone()
            .unwrap_or_else(|| crate::remote_signing::DEFAULT_SERVER_URL.to_string())
    }

    fn remote_signing_initiator(
        &self,
    ) -> Result<Option<Box<dyn SessionInitiatePeer>>, RemoteSignError> {
        let server_url = self.url();

        if let Some(public_key_data) = &self.public_key {
            let public_key_data = STANDARD_ENGINE.decode(public_key_data)?;

            Ok(Some(Box::new(PublicKeyInitiator::new(
                public_key_data,
                Some(server_url),
            )?)))
        } else if let Some(path) = &self.public_key_pem_path {
            let pem_data = std::fs::read(path)?;
            let doc = pem::parse(pem_data)?;

            let spki_der = match doc.tag() {
                "PUBLIC KEY" => doc.contents().to_vec(),
                "CERTIFICATE" => {
                    let cert = CapturedX509Certificate::from_der(doc.contents())?;
                    cert.to_public_key_der()?.as_ref().to_vec()
                }
                tag => {
                    error!(
                        "unknown PEM format: {}; only `PUBLIC KEY` and `CERTIFICATE` are parsed",
                        tag
                    );
                    return Err(RemoteSignError::Crypto("invalid public key data".into()));
                }
            };

            Ok(Some(Box::new(PublicKeyInitiator::new(
                spki_der,
                Some(server_url),
            )?)))
        } else if let Some(env) = &self.shared_secret_env {
            let secret = std::env::var(env).map_err(|_| {
                RemoteSignError::ClientState(
                    "failed reading from shared secret environment variable",
                )
            })?;

            Ok(Some(Box::new(SharedSecretInitiator::new(
                secret.as_bytes().to_vec(),
            )?)))
        } else if let Some(value) = &self.shared_secret {
            Ok(Some(Box::new(SharedSecretInitiator::new(
                value.as_bytes().to_vec(),
            )?)))
        } else {
            Ok(None)
        }
    }
}

#[derive(Args, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateDerSigningKey {
    /// Path to file containing DER encoded certificate data
    #[arg(
        id = "certificate_der_paths",
        long = "certificate-der-file",
        alias = "der-source",
        alias = "der-file",
        value_name = "PATH"
    )]
    pub paths: Vec<PathBuf>,
}

impl KeySource for CertificateDerSigningKey {
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        let mut res = SigningCertificates::default();

        for path in &self.paths {
            warn!("reading DER file {}", path.display());
            let der_data = std::fs::read(path)?;

            res.certs.push(CapturedX509Certificate::from_der(der_data)?);
        }

        Ok(res)
    }
}

#[derive(Args, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateSource {
    #[command(flatten)]
    #[serde(default, rename = "smartcard", skip_serializing_if = "Option::is_none")]
    pub smartcard_key: Option<SmartcardSigningKey>,

    #[command(flatten)]
    #[serde(
        default,
        rename = "macos_keychain",
        skip_serializing_if = "Option::is_none"
    )]
    pub macos_keychain_key: Option<MacosKeychainSigningKey>,

    #[command(flatten)]
    #[serde(
        default,
        rename = "windows_store",
        skip_serializing_if = "Option::is_none"
    )]
    pub windows_store_key: Option<WindowsStoreSigningKey>,

    #[command(flatten)]
    #[serde(default, rename = "pem", skip_serializing_if = "Option::is_none")]
    pub pem_path_key: Option<PemSigningKey>,

    #[command(flatten)]
    #[serde(default, rename = "p12", skip_serializing_if = "Option::is_none")]
    pub p12_key: Option<P12SigningKey>,

    #[command(flatten)]
    #[serde(default, rename = "pkcs11", skip_serializing_if = "Option::is_none")]
    pub pkcs11_key: Option<Pkcs11SigningKey>,

    #[command(flatten)]
    #[serde(default, rename = "remote", skip_serializing_if = "Option::is_none")]
    pub remote_signing_key: Option<RemoteSigningKey>,

    #[command(flatten)]
    #[serde(
        default,
        rename = "certificate_der",
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_der_key: Option<CertificateDerSigningKey>,
}

impl CertificateSource {
    /// Obtain a reference to all [KeySource] present.
    pub fn key_sources(&self, scan_smartcard: bool) -> Vec<&dyn KeySource> {
        let mut res = vec![];

        if scan_smartcard {
            if let Some(key) = &self.smartcard_key {
                res.push(key as &dyn KeySource);
            }
        }

        if let Some(key) = &self.macos_keychain_key {
            res.push(key as &dyn KeySource);
        }

        if let Some(key) = &self.windows_store_key {
            res.push(key as &dyn KeySource);
        }

        if let Some(key) = &self.pem_path_key {
            res.push(key as &dyn KeySource);
        }

        if let Some(key) = &self.p12_key {
            res.push(key as &dyn KeySource);
        }

        if let Some(key) = &self.pkcs11_key {
            res.push(key as &dyn KeySource);
        }

        if let Some(key) = &self.remote_signing_key {
            res.push(key as &dyn KeySource);
        }

        if let Some(key) = &self.certificate_der_key {
            res.push(key as &dyn KeySource);
        }

        res
    }

    pub fn resolve_certificates(
        &self,
        scan_smartcard: bool,
    ) -> Result<SigningCertificates, AppleCodesignError> {
        let mut res = SigningCertificates::default();

        for key in self.key_sources(scan_smartcard) {
            let certs = key.resolve_certificates()?;

            if key.exclusive() && !certs.is_empty() {
                return Ok(certs);
            }

            res.extend(certs);
        }

        Ok(res)
    }
}

#[derive(Args, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pkcs11SigningKey {
    /// Path to PKCS11 library (.so/.dylib/.dll)
    #[arg(long = "pkcs11-library", value_name = "PATH")]
    pub library_path: Option<PathBuf>,

    /// PKCS11 token label to use
    #[arg(long = "pkcs11-token-label", value_name = "LABEL")]
    pub token_label: Option<String>,

    /// PKCS11 slot ID to use (alternative to token label)
    #[arg(long = "pkcs11-slot-id", value_name = "ID")]
    pub slot_id: Option<u64>,

    /// PIN for PKCS11 token
    #[arg(long = "pkcs11-pin", value_name = "SECRET")]
    pub pkcs11_pin: Option<String>,

    /// Environment variable holding the PKCS11 PIN
    #[arg(long = "pkcs11-pin-env", value_name = "STRING")]
    #[serde(skip)]
    pub pkcs11_pin_env: Option<String>,

    /// Path to certificate file (PEM/DER)
    #[arg(long = "pkcs11-certificate-file", value_name = "PATH")]
    pub certificate_file: Option<PathBuf>,

    /// Private key label in PKCS11 token (CKA_LABEL attribute)
    #[arg(long = "pkcs11-key-label", value_name = "LABEL")]
    pub key_label: Option<String>,

    /// Private key ID in PKCS11 token (CKA_ID attribute)
    #[arg(long = "pkcs11-key-id", value_name = "ID")]
    pub key_id: Option<String>,
}

impl KeySource for Pkcs11SigningKey {
    #[cfg(feature = "pkcs11")]
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        let library_path = match &self.library_path {
            Some(path) => path.clone(),
            None => return Ok(Default::default()),
        };

        info!("initializing PKCS11 library: {}", library_path.display());

        let pkcs11 = Pkcs11::new(library_path.clone())?;
        pkcs11.initialize(CInitializeArgs::OsThreads).or_else(|e| {
            match e {
                cryptoki::error::Error::AlreadyInitialized => {
                    info!("PKCS11 library already initialized");
                    Ok(())
                }
                _ => Err(e),
            }
        })?;

        let slots = pkcs11.get_slots_with_token()?;
        if slots.is_empty() {
            return Err(AppleCodesignError::Pkcs11Error("no PKCS11 tokens found".into()));
        }

        // Find the right slot
        let slot = if let Some(slot_id) = self.slot_id {
            slots.into_iter()
                .find(|s| s.id() == slot_id)
                .ok_or_else(|| AppleCodesignError::Pkcs11Error(format!("PKCS11 slot {} not found", slot_id)))?
        } else if let Some(token_label) = &self.token_label {
            let target_label = token_label.trim();
            slots.into_iter()
                .find(|slot| {
                    if let Ok(token_info) = pkcs11.get_token_info(*slot) {
                        let label = String::from_utf8_lossy(&token_info.label().as_bytes()).trim().to_string();
                        label == target_label
                    } else {
                        false
                    }
                })
                .ok_or_else(|| AppleCodesignError::Pkcs11Error(format!("PKCS11 token '{}' not found", target_label)))?
        } else {
            slots[0] // Use first slot if no preference specified
        };

        info!("using PKCS11 slot: {}", slot.id());

        // Load certificate from local file
        let cert = if let Some(cert_file) = &self.certificate_file {
            // Load certificate from local file (similar to osslsigncode)
            info!("loading certificate from local file: {}", cert_file.display());
            self.load_certificate_from_file(cert_file)?
        } else {
            return Err(AppleCodesignError::Pkcs11Error(
                "--pkcs11-certificate-file is required for Apple code signing workflows".into()
            ));
        };

        info!("loaded certificate: {}", cert.subject_common_name().unwrap_or_else(|| "unknown".into()));

        // Create PKCS11 private key wrapper
        let pkcs11_key = if let Some(key_id) = &self.key_id {
            // Use CKA_ID attribute
            Pkcs11PrivateKey::new_with_id(
                library_path,
                slot.id(),
                key_id.clone(),
                self.get_pin()?,
                cert.clone(),
            )?
        } else if let Some(key_label) = &self.key_label {
            // Use CKA_LABEL attribute
            Pkcs11PrivateKey::new_with_label(
                library_path,
                slot.id(),
                key_label.clone(),
                self.get_pin()?,
                cert.clone(),
            )?
        } else {
            // Try to find private key automatically based on certificate
            info!("attempting automatic private key discovery");
            Pkcs11PrivateKey::new_from_certificate(
                library_path,
                slot.id(),
                self.get_pin()?,
                cert.clone(),
            )?
        };

        Ok(SigningCertificates {
            keys: vec![Box::new(pkcs11_key)],
            certs: vec![cert],
        })
    }

    #[cfg(not(feature = "pkcs11"))]
    fn resolve_certificates(&self) -> Result<SigningCertificates, AppleCodesignError> {
        if self.library_path.is_some() {
            error!("PKCS11 support not available; ignoring --pkcs11-* arguments");
        }
        Ok(Default::default())
    }
}

#[cfg(feature = "pkcs11")]
impl Pkcs11SigningKey {
    fn get_pin(&self) -> Result<Option<String>, AppleCodesignError> {
        if let Some(pin) = &self.pkcs11_pin {
            Ok(Some(pin.clone()))
        } else if let Some(pin_env) = &self.pkcs11_pin_env {
            match std::env::var(pin_env) {
                Ok(pin) => {
                    info!("using PIN from {} environment variable", pin_env);
                    Ok(Some(pin))
                }
                Err(_) => {
                    error!("failed to read PIN from environment variable: {}", pin_env);
                    Err(AppleCodesignError::Pkcs11Error(format!(
                        "PIN environment variable {} not found", pin_env
                    )))
                }
            }
        } else {
            Ok(None)
        }
    }

    fn load_certificate_from_file(&self, cert_file: &PathBuf) -> Result<CapturedX509Certificate, AppleCodesignError> {
        let cert_data = std::fs::read(cert_file)?;

        // Try PEM first
        if let Ok(pem) = pem::parse(&cert_data) {
            if pem.tag() == "CERTIFICATE" {
                return CapturedX509Certificate::from_der(pem.contents()).map_err(|e| {
                    AppleCodesignError::Pkcs11Error(format!(
                        "failed to parse PEM certificate from file {}: {}",
                        cert_file.display(),
                        e
                    ))
                });
            }
        }

        // Try DER
        CapturedX509Certificate::from_der(cert_data).map_err(|e| {
            AppleCodesignError::Pkcs11Error(format!(
                "failed to parse certificate from file {}: {}",
                cert_file.display(),
                e
            ))
        })
    }


}
