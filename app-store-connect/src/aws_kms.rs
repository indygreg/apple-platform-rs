// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ES256 JWT signing backed by AWS KMS.
//!
//! This allows the App Store Connect API private key (an ECDSA P-256 key)
//! to live in AWS KMS so that the key material is never exposed to the
//! machine performing notarization.
//!
//! AWS credentials are resolved through the standard SDK default provider
//! chain, which includes web identity federation (OIDC) via the
//! `AWS_WEB_IDENTITY_TOKEN_FILE` / `AWS_ROLE_ARN` environment variables.

use {
    crate::{api_token::Es256Signer, Result},
    anyhow::anyhow,
    aws_sdk_kms::{
        error::DisplayErrorContext,
        primitives::Blob,
        types::{MessageType, SigningAlgorithmSpec},
    },
    sha2::{Digest, Sha256},
};

/// An [Es256Signer] that signs with an ECDSA P-256 key held in AWS KMS.
pub struct AwsKmsEs256Signer {
    key_id: String,
    client: aws_sdk_kms::Client,
    rt: tokio::runtime::Runtime,
}

impl AwsKmsEs256Signer {
    /// Construct an instance from a KMS key ID, key ARN, or alias.
    ///
    /// `region`, if given, overrides the region from the environment / profile.
    pub fn new(key_id: String, region: Option<String>) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = region {
            loader = loader.region(aws_sdk_kms::config::Region::new(region));
        }

        let config = rt.block_on(loader.load());
        let client = aws_sdk_kms::Client::new(&config);

        Ok(Self { key_id, client, rt })
    }

    /// The KMS key ID, key ARN, or alias this signer uses.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl Es256Signer for AwsKmsEs256Signer {
    fn sign_es256(&self, message: &[u8]) -> Result<Vec<u8>> {
        let digest = Sha256::digest(message).to_vec();

        let response = self
            .rt
            .block_on(
                self.client
                    .sign()
                    .key_id(&self.key_id)
                    .message(Blob::new(digest))
                    .message_type(MessageType::Digest)
                    .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                    .send(),
            )
            .map_err(|e| {
                anyhow!(
                    "AWS KMS Sign failed for key {}: {}",
                    self.key_id,
                    DisplayErrorContext(&e)
                )
            })?;

        let der_signature = response
            .signature()
            .ok_or_else(|| anyhow!("AWS KMS Sign response missing signature"))?
            .as_ref();

        // KMS returns ECDSA signatures in ASN.1 DER form. JWS ES256 requires
        // the raw 64 byte r || s encoding (RFC 7518 section 3.4).
        let signature = p256::ecdsa::Signature::from_der(der_signature)
            .map_err(|e| anyhow!("failed to parse KMS ECDSA signature: {e}"))?;

        Ok(signature.to_bytes().to_vec())
    }
}
