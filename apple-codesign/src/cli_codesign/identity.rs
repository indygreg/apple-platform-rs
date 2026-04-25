// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `-s identity` / `--keychain` resolution into [`SigningCertificates`].

use {
    crate::{
        cli::certificate_source::SigningCertificates,
        cli::get_pkcs12_password,
        cryptography::{parse_pfx_data, InMemoryPrivateKey},
        error::AppleCodesignError,
    },
    log::{info, warn},
    std::path::{Path, PathBuf},
    x509_certificate::CapturedX509Certificate,
};

#[cfg(target_os = "macos")]
use crate::macos::{keychain_find_code_signing_certificates, KeychainDomain};

/// The choice encoded by the `-s` argument.
pub enum IdentityChoice<'a> {
    /// `-s -` — ad-hoc (no CMS signature, just digests).
    AdHoc,
    /// 40 hex characters: SHA-1 fingerprint of the signing certificate.
    Sha1Fingerprint(&'a str),
    /// Substring of the subject common name (case-sensitive).
    CommonNameSubstring(&'a str),
}

impl<'a> IdentityChoice<'a> {
    pub fn parse(identity: &'a str) -> Self {
        if identity == "-" {
            return IdentityChoice::AdHoc;
        }
        if identity.len() == 40 && identity.chars().all(|c| c.is_ascii_hexdigit()) {
            return IdentityChoice::Sha1Fingerprint(identity);
        }
        IdentityChoice::CommonNameSubstring(identity)
    }
}

/// Resolve the identity + optional `--keychain` argument into a set of
/// certificates ready for [`SigningCertificates::load_into_signing_settings`].
///
/// `keychain` is interpreted by file extension:
///
/// * `.p12` / `.pfx` → reads the PKCS#12 bundle; password is prompted from
///   stdin unless supplied by the usual environment.
/// * `.pem` → reads PEM-encoded certificates and private keys.
/// * anything else on macOS → honored by keychain search (not yet wired;
///   today the value is logged and ignored).
pub fn resolve(
    identity: &str,
    keychain: Option<&Path>,
) -> Result<SigningCertificates, AppleCodesignError> {
    let choice = IdentityChoice::parse(identity);

    // If the user gave us a file-like --keychain, that wins: it is the
    // cross-platform way to sign and matches how Apple's codesign uses the
    // flag when the value is a path (rather than a named keychain).
    if let Some(path) = keychain {
        if is_p12_path(path) {
            return from_p12(path);
        }
        if is_pem_path(path) {
            return from_pem(path);
        }
        #[cfg(not(target_os = "macos"))]
        {
            return Err(AppleCodesignError::CliGeneralError(format!(
                "--keychain {}: unrecognized extension on non-macOS host; \
                 use .p12/.pfx or .pem to supply a key bundle",
                path.display()
            )));
        }
        #[cfg(target_os = "macos")]
        {
            warn!(
                "--keychain {} refers to a macOS keychain file; honoring it \
                 as a search-list extension is not implemented yet — the \
                 default keychain search list will be used",
                path.display()
            );
        }
    }

    match choice {
        IdentityChoice::AdHoc => Ok(SigningCertificates::default()),
        IdentityChoice::Sha1Fingerprint(hex) => resolve_from_keychain_sha1(hex),
        IdentityChoice::CommonNameSubstring(s) => resolve_from_keychain_cn(s),
    }
}

fn is_p12_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase),
        Some(ref ext) if ext == "p12" || ext == "pfx"
    )
}

fn is_pem_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase),
        Some(ref ext) if ext == "pem"
    )
}

fn from_p12(path: &Path) -> Result<SigningCertificates, AppleCodesignError> {
    let data = std::fs::read(path)?;
    let password = get_pkcs12_password(None::<String>, None::<PathBuf>)?;
    let (cert, private_key) = parse_pfx_data(&data, &password)?;
    info!("loaded p12 certificate from {}", path.display());
    Ok(SigningCertificates {
        keys: vec![Box::new(private_key)],
        certs: vec![cert],
    })
}

fn from_pem(path: &Path) -> Result<SigningCertificates, AppleCodesignError> {
    let pem_data = std::fs::read(path)?;
    let mut res = SigningCertificates::default();
    for pem in pem::parse_many(pem_data).map_err(AppleCodesignError::CertificatePem)? {
        match pem.tag() {
            "CERTIFICATE" => {
                res.certs
                    .push(CapturedX509Certificate::from_der(pem.contents())?);
            }
            "PRIVATE KEY" => {
                res.keys.push(Box::new(InMemoryPrivateKey::from_pkcs8_der(
                    pem.contents(),
                )?));
            }
            "RSA PRIVATE KEY" => {
                res.keys.push(Box::new(InMemoryPrivateKey::from_pkcs1_der(
                    pem.contents(),
                )?));
            }
            tag => warn!("(unhandled PEM tag {tag}; ignoring)"),
        }
    }
    Ok(res)
}

#[cfg(target_os = "macos")]
fn resolve_from_keychain_sha1(hex: &str) -> Result<SigningCertificates, AppleCodesignError> {
    for domain in [
        KeychainDomain::User,
        KeychainDomain::Common,
        KeychainDomain::System,
    ] {
        for cert in keychain_find_code_signing_certificates(domain, None)? {
            let captured = cert.as_captured_x509_certificate();
            let got = hex::encode(captured.sha1_fingerprint()?.as_ref());
            if got.eq_ignore_ascii_case(hex) {
                info!("matched keychain certificate by SHA-1 fingerprint");
                return Ok(SigningCertificates {
                    keys: vec![Box::new(cert)],
                    certs: vec![captured],
                });
            }
        }
    }
    Err(AppleCodesignError::CliGeneralError(format!(
        "no code-signing identity in the keychain matched SHA-1 {hex}"
    )))
}

#[cfg(target_os = "macos")]
fn resolve_from_keychain_cn(substring: &str) -> Result<SigningCertificates, AppleCodesignError> {
    let mut exact: Vec<_> = Vec::new();
    let mut partial: Vec<_> = Vec::new();

    for domain in [
        KeychainDomain::User,
        KeychainDomain::Common,
        KeychainDomain::System,
    ] {
        for cert in keychain_find_code_signing_certificates(domain, None)? {
            let captured = cert.as_captured_x509_certificate();
            let Some(cn) = captured.subject_common_name() else {
                continue;
            };
            if cn == substring {
                exact.push((cert, captured));
            } else if cn.contains(substring) {
                partial.push((cert, captured));
            }
        }
    }

    let chosen = if exact.len() == 1 {
        exact.into_iter().next()
    } else if exact.is_empty() && partial.len() == 1 {
        partial.into_iter().next()
    } else if !exact.is_empty() {
        return Err(AppleCodesignError::CliGeneralError(format!(
            "identity {substring:?} has {} exact matches in the keychain; \
             refusing to guess",
            exact.len()
        )));
    } else if partial.len() > 1 {
        return Err(AppleCodesignError::CliGeneralError(format!(
            "identity {substring:?} matches {} common names in the keychain; \
             refusing to guess",
            partial.len()
        )));
    } else {
        None
    };

    let Some((cert, captured)) = chosen else {
        return Err(AppleCodesignError::CliGeneralError(format!(
            "no code-signing identity in the keychain matched {substring:?}"
        )));
    };

    info!("matched keychain certificate by common name substring");
    Ok(SigningCertificates {
        keys: vec![Box::new(cert)],
        certs: vec![captured],
    })
}

#[cfg(not(target_os = "macos"))]
fn resolve_from_keychain_sha1(_hex: &str) -> Result<SigningCertificates, AppleCodesignError> {
    Err(AppleCodesignError::CliGeneralError(
        "keychain identity lookup requires macOS; pass --keychain with a \
         .p12 or .pem file instead"
            .into(),
    ))
}

#[cfg(not(target_os = "macos"))]
fn resolve_from_keychain_cn(_s: &str) -> Result<SigningCertificates, AppleCodesignError> {
    Err(AppleCodesignError::CliGeneralError(
        "keychain identity lookup requires macOS; pass --keychain with a \
         .p12 or .pem file instead"
            .into(),
    ))
}
