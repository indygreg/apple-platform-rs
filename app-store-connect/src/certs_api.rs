// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{AppStoreConnectClient, Result};
use base64::{engine::general_purpose::STANDARD as STANDARD_ENGINE, Engine};
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use x509_certificate::{InMemorySigningKeyPair, X509CertificateBuilder};

pub fn generate_signing_certificate(api_key: &Path, ty: CertificateType, pem: &Path) -> Result<()> {
    let secret = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let key = InMemorySigningKeyPair::from_pkcs8_der(secret.to_pkcs8_der()?.as_bytes())?;
    let mut builder = X509CertificateBuilder::default();
    builder
        .subject()
        .append_common_name_utf8_string("Apple Code Signing CSR")
        .expect("only valid chars");
    let csr = builder
        .create_certificate_signing_request(&key)?
        .encode_pem()?;
    let cer = AppStoreConnectClient::from_json_path(api_key)?
        .create_certificate(csr, ty)?
        .data
        .attributes
        .certificate_content;
    let cer = pem::encode(&pem::Pem::new("CERTIFICATE", STANDARD_ENGINE.decode(cer)?));
    let mut f = File::create(pem)?;
    f.write_all(secret.to_pkcs8_pem(LineEnding::CRLF)?.as_bytes())?;
    f.write_all(cer.as_bytes())?;
    Ok(())
}

const APPLE_CERTIFICATE_URL: &str = "https://api.appstoreconnect.apple.com/v1/certificates";

impl AppStoreConnectClient {
    pub fn create_certificate(
        &self,
        csr: String,
        ty: CertificateType,
    ) -> Result<CertificateResponse> {
        let token = self.get_token()?;
        let body = CertificateCreateRequest {
            data: CertificateCreateRequestData {
                attributes: CertificateCreateRequestAttributes {
                    certificate_type: ty.to_string(),
                    csr_content: csr,
                },
                r#type: "certificates".into(),
            },
        };
        let req = self
            .client
            .post(APPLE_CERTIFICATE_URL)
            .bearer_auth(token)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body);
        Ok(self.send_request(req)?.json()?)
    }

    pub fn list_certificates(&self) -> Result<CertificatesResponse> {
        let token = self.get_token()?;
        let req = self
            .client
            .get(APPLE_CERTIFICATE_URL)
            .bearer_auth(token)
            .header("Accept", "application/json");
        Ok(self.send_request(req)?.json()?)
    }

    pub fn get_certificate(&self, id: &str) -> Result<CertificateResponse> {
        let token = self.get_token()?;
        let req = self
            .client
            .get(format!("{APPLE_CERTIFICATE_URL}/{id}"))
            .bearer_auth(token)
            .header("Accept", "application/json");
        Ok(self.send_request(req)?.json()?)
    }

    pub fn revoke_certificate(&self, id: &str) -> Result<()> {
        let token = self.get_token()?;
        let req = self
            .client
            .delete(format!("{APPLE_CERTIFICATE_URL}/{id}"))
            .bearer_auth(token);
        self.send_request(req)?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateCreateRequest {
    pub data: CertificateCreateRequestData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateCreateRequestData {
    pub attributes: CertificateCreateRequestAttributes,
    pub r#type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateCreateRequestAttributes {
    pub certificate_type: String,
    pub csr_content: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum CertificateType {
    Development,
    Distribution,
    DeveloperIdApplication,
}

impl std::fmt::Display for CertificateType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::Development => "DEVELOPMENT",
            Self::Distribution => "DISTRIBUTION",
            Self::DeveloperIdApplication => "DEVELOPER_ID_APPLICATION",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateResponse {
    pub data: Certificate,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificatesResponse {
    pub data: Vec<Certificate>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    pub attributes: CertificateAttributes,
    pub id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAttributes {
    pub certificate_content: String,
    pub display_name: String,
    pub expiration_date: String,
    pub name: String,
    pub platform: Option<String>,
    pub serial_number: String,
    pub certificate_type: String,
}
