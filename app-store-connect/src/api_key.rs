// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! API Key

use {
    crate::{ConnectTokenEncoder, Error, Result},
    anyhow::Context,
    base64::{engine::general_purpose::STANDARD as STANDARD_ENGINE, Engine},
    serde::{Deserialize, Serialize},
    std::{fs::Permissions, io::Write, path::Path},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn set_permissions_private(p: &mut Permissions) {
    p.set_mode(0o600);
}

#[cfg(windows)]
fn set_permissions_private(_: &mut Permissions) {}

/// Represents all metadata for an App Store Connect API Key.
///
/// This is a convenience type to aid in the generic representation of all the components
/// of an App Store Connect API Key. The type supports serialization so we save as a single
/// file or payload to enhance usability (so people don't need to provide all 3 pieces of the
/// API Key for all operations).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnifiedApiKey {
    /// Who issued the key.
    ///
    /// Likely a UUID.
    issuer_id: String,

    /// Key identifier.
    ///
    /// An alphanumeric string like `DEADBEEF42`.
    key_id: String,

    /// Base64 encoded DER of ECDSA private key material.
    ///
    /// Mutually exclusive with `aws_kms_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,

    /// AWS KMS key ID, key ARN, or alias ARN holding the private key.
    ///
    /// When set, signing operations are performed remotely via AWS KMS and
    /// this file contains no secret material. Mutually exclusive with
    /// `private_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aws_kms_key: Option<String>,

    /// AWS region of the KMS key (optional; overrides environment / profile).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aws_kms_region: Option<String>,
}

impl UnifiedApiKey {
    /// Construct an instance from constitute parts and a PEM encoded ECDSA private key.
    ///
    /// This is what you want to use if importing a private key from the file downloaded
    /// from the App Store Connect web interface.
    pub fn from_ecdsa_pem_path(
        issuer_id: impl ToString,
        key_id: impl ToString,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let pem_data = std::fs::read(path.as_ref())?;

        let parsed = pem::parse(pem_data).map_err(|_| InvalidPemPrivateKey)?;

        if parsed.tag() != "PRIVATE KEY" {
            return Err(InvalidPemPrivateKey.into());
        }

        let private_key = STANDARD_ENGINE.encode(parsed.contents());

        Ok(Self {
            issuer_id: issuer_id.to_string(),
            key_id: key_id.to_string(),
            private_key: Some(private_key),
            aws_kms_key: None,
            aws_kms_region: None,
        })
    }

    /// Construct an instance referencing a private key held in AWS KMS.
    ///
    /// The resulting instance (and its JSON serialization) contains no
    /// secret material: signing requires AWS credentials authorized to
    /// use the referenced KMS key.
    pub fn from_aws_kms_key(
        issuer_id: impl ToString,
        key_id: impl ToString,
        aws_kms_key: impl ToString,
        aws_kms_region: Option<String>,
    ) -> Self {
        Self {
            issuer_id: issuer_id.to_string(),
            key_id: key_id.to_string(),
            private_key: None,
            aws_kms_key: Some(aws_kms_key.to_string()),
            aws_kms_region,
        }
    }

    /// Construct an instance from serialized JSON.
    pub fn from_json(data: impl AsRef<[u8]>) -> Result<Self> {
        Ok(serde_json::from_slice(data.as_ref())?)
    }

    /// Construct an instance from a JSON file.
    pub fn from_json_path(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path.as_ref())?;

        Self::from_json(data)
    }

    /// Serialize this instance to a JSON object.
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self)?)
    }

    /// Write this instance to a JSON file.
    ///
    /// Since the file contains sensitive data, it will have limited read permissions
    /// on platforms where this is implemented. Parent directories will be created if missing
    /// using default permissions for created directories.
    ///
    /// Permissions on the resulting file may not be as restrictive as desired. It is up
    /// to callers to additionally harden as desired.
    pub fn write_json_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let data = self.to_json_string()?;

        let mut fh = std::fs::File::create(path)?;
        let mut permissions = fh.metadata()?.permissions();
        set_permissions_private(&mut permissions);
        fh.set_permissions(permissions)?;
        fh.write_all(data.as_bytes())?;

        Ok(())
    }
}

impl TryFrom<UnifiedApiKey> for ConnectTokenEncoder {
    type Error = anyhow::Error;

    fn try_from(value: UnifiedApiKey) -> Result<Self> {
        if let Some(private_key) = value.private_key {
            let der = STANDARD_ENGINE
                .decode(private_key)
                .context("invalid unified api key")?;

            return Self::from_ecdsa_der(value.key_id, value.issuer_id, &der);
        }

        if let Some(kms_key) = value.aws_kms_key {
            #[cfg(feature = "aws-kms")]
            {
                let signer =
                    crate::aws_kms::AwsKmsEs256Signer::new(kms_key, value.aws_kms_region)?;

                return Ok(Self::from_es256_signer(
                    value.key_id,
                    value.issuer_id,
                    std::sync::Arc::new(signer),
                ));
            }

            #[cfg(not(feature = "aws-kms"))]
            {
                return Err(anyhow::anyhow!(
                    "unified api key references AWS KMS key {kms_key} but AWS KMS support \
                     is not compiled in (enable the `aws-kms` Cargo feature)"
                ));
            }
        }

        Err(anyhow::anyhow!(
            "unified api key defines neither `private_key` nor `aws_kms_key`"
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("invalid PEM formatted private key")]
pub struct InvalidPemPrivateKey;
