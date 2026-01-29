//! Using the AWS Key Management Service to sign binaries.
//! This uses the AWS SDK, which accepts authentication in similar ways to the
//! CLI: <https://docs.aws.amazon.com/sdkref/latest/guide/access.html>
//!
//! Example:
//! ```
//! rcodesign sign --aws-kms-key-id 'arn:aws:kms:us-east-1:123456781234:key/12345678-1234-1234-1234-123456789123' --aws-kms-certificate-file ./cert.pem.crt ./rcodesign
//! ```
//!
//! For testing, you can use a rather annoying key wrapping procedure to
//! import the keys from `rcodesign generate-self-signed-certificate` to KMS:
//! <https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-conceptual.html>
//!
//! Alternatively, you can create a CSR from the KMS public key and then self
//! sign it.

use std::sync::Arc;

use aws_config::BehaviorVersion;
use bcder::{decode::Constructed, Mode};
use signature::Signer;
use x509_certificate::{
    rfc5280::SubjectPublicKeyInfo, KeyAlgorithm, KeyInfoSigner, Sign, Signature,
    SignatureAlgorithm, X509CertificateError,
};

use aws_sdk_kms::types::SigningAlgorithmSpec as AWSSigningAlgorithm;

use crate::{cryptography::PrivateKey, AppleCodesignError};

pub struct KMSSigner {
    pub runtime: tokio::runtime::Runtime,
    client: aws_sdk_kms::Client,
}

impl KMSSigner {
    pub fn new() -> Result<Arc<KMSSigner>, AppleCodesignError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let config = runtime.block_on(aws_config::load_defaults(BehaviorVersion::v2026_01_12()));
        let client = aws_sdk_kms::Client::new(&config);
        Ok(Arc::new(KMSSigner { runtime, client }))
    }
}

pub struct AWSKMSKey {
    signer: Arc<KMSSigner>,
    public_key_info: SubjectPublicKeyInfo,
    key_id: String,
}

impl AWSKMSKey {
    pub async fn new(
        signer: Arc<KMSSigner>,
        key_id: String,
    ) -> Result<AWSKMSKey, AppleCodesignError> {
        let pubkey_resp = signer
            .client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .map_err(|e| {
                AppleCodesignError::AWSKMSGetPublicKeyError(
                    aws_smithy_types::error::display::DisplayErrorContext(e).into(),
                )
            })?;

        let pubkey = pubkey_resp
            .public_key
            .ok_or(AppleCodesignError::AWSKMSError(
                "missing pubkey in pubkey response".to_owned(),
            ))?;

        let actual_pubkey =
            Constructed::decode(pubkey.as_ref(), Mode::Der, SubjectPublicKeyInfo::take_from)
                .map_err(|e| {
                    AppleCodesignError::AWSKMSError(format!("Non-decodable DER from AWS?! {}", e))
                })?;

        Ok(AWSKMSKey {
            signer,
            public_key_info: actual_pubkey,
            key_id,
        })
    }

    pub fn public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.public_key_info
    }

    fn choose_signature_algorithm(
        &self,
    ) -> Result<(SignatureAlgorithm, AWSSigningAlgorithm), String> {
        let algorithm = self
            .key_algorithm()
            .ok_or_else(|| "Cannot determine key algorithm from certificate".to_owned())?;

        // For reference: <https://github.com/aws-samples/diy-code-signing-kms-private-ca/blob/master/src/main/java/com/amazonaws/acmpcakms/examples/algorithms/ecc/ECP384Family.java>
        Ok(match algorithm {
            KeyAlgorithm::Ecdsa(_) => (
                SignatureAlgorithm::EcdsaSha384,
                AWSSigningAlgorithm::EcdsaSha384,
            ),
            KeyAlgorithm::Rsa => (
                SignatureAlgorithm::RsaSha384,
                AWSSigningAlgorithm::RsassaPkcs1V15Sha384,
            ),
            _ => {
                return Err(format!(
                    "Unsupported key algorithm for AWS KMS: {:?}",
                    algorithm
                ))
            }
        })
    }
}

impl Signer<Signature> for AWSKMSKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let (_alg, aws_algorithm) = self
            .choose_signature_algorithm()
            .map_err(signature::Error::from_source)?;

        let sig = self
            .signer
            .runtime
            .block_on(
                self.signer
                    .client
                    .sign()
                    .key_id(&self.key_id)
                    .signing_algorithm(aws_algorithm)
                    .message(msg.into())
                    .send(),
            )
            .map_err(|e| {
                signature::Error::from_source(AppleCodesignError::AWSKMSSignError(
                    aws_smithy_types::error::display::DisplayErrorContext(e).into(),
                ))
            })?;

        Ok(sig
            .signature
            .ok_or(signature::Error::from_source(
                "AWS KMS gave us no signature. This should not occur".to_owned(),
            ))?
            .into_inner()
            .into())
    }
}

impl Sign for AWSKMSKey {
    fn sign(
        &self,
        message: &[u8],
    ) -> Result<
        (Vec<u8>, x509_certificate::SignatureAlgorithm),
        x509_certificate::X509CertificateError,
    > {
        // NOTE: This function isn't actually used anywhere AFAIK.
        let (algorithm, _aws_algorithm) = self
            .choose_signature_algorithm()
            .map_err(X509CertificateError::Other)?;
        Ok((self.try_sign(message)?.into(), algorithm))
    }

    fn key_algorithm(&self) -> Option<x509_certificate::KeyAlgorithm> {
        KeyAlgorithm::try_from(&self.public_key_info.algorithm).ok()
    }

    fn public_key_data(&self) -> bytes::Bytes {
        self.public_key_info.subject_public_key.octet_bytes()
    }

    fn signature_algorithm(
        &self,
    ) -> Result<x509_certificate::SignatureAlgorithm, x509_certificate::X509CertificateError> {
        Ok(self
            .choose_signature_algorithm()
            .map_err(X509CertificateError::UnknownSignatureAlgorithm)?
            .0)
    }

    fn private_key_data(&self) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        // This is simply not obtainable.
        None
    }

    fn rsa_primes(
        &self,
    ) -> Result<
        Option<(zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<Vec<u8>>)>,
        x509_certificate::X509CertificateError,
    > {
        // This is also a private key.
        Ok(None)
    }
}

impl KeyInfoSigner for AWSKMSKey {}

impl PrivateKey for AWSKMSKey {
    fn as_key_info_signer(&self) -> &dyn x509_certificate::KeyInfoSigner {
        self
    }

    fn to_public_key_peer_decrypt(
        &self,
    ) -> Result<
        Box<dyn crate::remote_signing::session_negotiation::PublicKeyPeerDecrypt>,
        AppleCodesignError,
    > {
        Err(AppleCodesignError::AWSKMSError(
            "Remote signing is not supported with KMS yet".to_owned(),
        ))
    }

    fn finish(&self) -> Result<(), AppleCodesignError> {
        Ok(())
    }
}
