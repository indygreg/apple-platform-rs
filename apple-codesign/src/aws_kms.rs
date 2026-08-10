// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! AWS KMS signing support.
//!
//! This module implements a signing key backend where the private key
//! material lives in AWS KMS and never leaves it. Signing operations are
//! performed remotely via the KMS `Sign` API.
//!
//! Credentials are resolved through the standard AWS SDK default provider
//! chain. This includes static credentials in the environment, shared
//! config/credentials files, IMDS, and - most useful for CI - web identity
//! federation via the `AWS_WEB_IDENTITY_TOKEN_FILE` / `AWS_ROLE_ARN`
//! environment variables (OIDC).

use {
    crate::{
        cryptography::PrivateKey,
        remote_signing::{session_negotiation::PublicKeyPeerDecrypt, RemoteSignError},
        AppleCodesignError,
    },
    aws_sdk_kms::{
        error::DisplayErrorContext,
        primitives::Blob,
        types::{KeySpec, MessageType, SigningAlgorithmSpec},
    },
    bytes::Bytes,
    der::Decode,
    log::{info, warn},
    signature::Signer,
    spki::EncodePublicKey,
    std::sync::Arc,
    x509_certificate::{
        CapturedX509Certificate, DigestAlgorithm, EcdsaCurve, KeyAlgorithm, KeyInfoSigner, Sign,
        Signature, SignatureAlgorithm, X509CertificateError,
    },
    zeroize::Zeroizing,
};

/// A signing key backed by AWS KMS.
///
/// The instance pairs a KMS asymmetric signing key (identified by key ID,
/// key ARN, or alias) with an optional X.509 certificate whose subject
/// public key is the public half of the KMS key. Without a certificate,
/// the instance can still be used for operations that only require the
/// key pair, like generating a certificate signing request.
#[derive(Clone)]
pub struct AwsKmsPrivateKey {
    key_id: String,
    key_algorithm: KeyAlgorithm,
    public_key_data: Bytes,
    certificate: Option<CapturedX509Certificate>,
    client: aws_sdk_kms::Client,
    rt: Arc<tokio::runtime::Runtime>,
}

impl AwsKmsPrivateKey {
    /// Construct a new instance from a KMS key identifier and an optional
    /// paired certificate.
    ///
    /// `region`, if given, overrides the region from the environment / profile.
    ///
    /// This calls the KMS `GetPublicKey` API to determine the key algorithm
    /// and, when a certificate is given, validate that its public key
    /// matches the KMS key. Construction therefore requires valid AWS
    /// credentials with `kms:GetPublicKey` permission on the key.
    pub fn new(
        key_id: String,
        certificate: Option<CapturedX509Certificate>,
        region: Option<String>,
    ) -> Result<Self, AppleCodesignError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = region {
            loader = loader.region(aws_sdk_kms::config::Region::new(region));
        }

        let config = rt.block_on(loader.load());
        let client = aws_sdk_kms::Client::new(&config);

        info!("retrieving public key for AWS KMS key {key_id}");

        let response = rt
            .block_on(client.get_public_key().key_id(&key_id).send())
            .map_err(|e| {
                AppleCodesignError::AwsKms(format!(
                    "GetPublicKey failed for key {}: {}",
                    key_id,
                    DisplayErrorContext(&e)
                ))
            })?;

        let kms_spki = response
            .public_key()
            .ok_or_else(|| {
                AppleCodesignError::AwsKms("KMS GetPublicKey response missing public key".into())
            })?
            .as_ref()
            .to_vec();

        let key_algorithm = match response.key_spec() {
            Some(KeySpec::Rsa2048) | Some(KeySpec::Rsa3072) | Some(KeySpec::Rsa4096) => {
                KeyAlgorithm::Rsa
            }
            Some(KeySpec::EccNistP256) => KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1),
            Some(KeySpec::EccNistP384) => KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1),
            spec => {
                return Err(AppleCodesignError::AwsKms(format!(
                    "unsupported KMS key spec for signing: {spec:?}"
                )))
            }
        };

        // The raw public key data (SPKI subjectPublicKey contents).
        let spki = spki::SubjectPublicKeyInfoOwned::from_der(&kms_spki).map_err(|e| {
            AppleCodesignError::AwsKms(format!("failed to parse KMS public key SPKI: {e}"))
        })?;
        let public_key_data = Bytes::copy_from_slice(spki.subject_public_key.raw_bytes());

        if let Some(cert) = &certificate {
            let cert_spki = cert
                .to_public_key_der()
                .map_err(|e| {
                    AppleCodesignError::AwsKms(format!(
                        "failed to encode certificate public key: {e}"
                    ))
                })?
                .as_ref()
                .to_vec();

            if kms_spki != cert_spki {
                return Err(AppleCodesignError::AwsKms(format!(
                    "certificate public key does not match public key of KMS key {key_id}; \
                     refusing to sign (was the certificate issued for a different key?)"
                )));
            }

            info!("certificate public key matches KMS key");
        }

        Ok(Self {
            key_id,
            key_algorithm,
            public_key_data,
            certificate,
            client,
            rt: Arc::new(rt),
        })
    }

    /// Resolve the KMS signing algorithm to use based on the key algorithm.
    fn signing_algorithm_spec(&self) -> Result<SigningAlgorithmSpec, AppleCodesignError> {
        match self.key_algorithm {
            KeyAlgorithm::Rsa => Ok(SigningAlgorithmSpec::RsassaPkcs1V15Sha256),
            KeyAlgorithm::Ecdsa(_) => Ok(SigningAlgorithmSpec::EcdsaSha256),
            algorithm => Err(AppleCodesignError::AwsKms(format!(
                "unsupported key algorithm for AWS KMS signing: {algorithm:?}"
            ))),
        }
    }

    /// Sign a pre-computed SHA-256 digest with the KMS key.
    fn kms_sign_digest(
        &self,
        digest: Vec<u8>,
        algorithm: SigningAlgorithmSpec,
    ) -> Result<Vec<u8>, AppleCodesignError> {
        info!(
            "signing {} byte digest with AWS KMS key {} using {:?}",
            digest.len(),
            self.key_id,
            algorithm
        );

        let response = self
            .rt
            .block_on(
                self.client
                    .sign()
                    .key_id(&self.key_id)
                    .message(Blob::new(digest))
                    .message_type(MessageType::Digest)
                    .signing_algorithm(algorithm)
                    .send(),
            )
            .map_err(|e| {
                AppleCodesignError::AwsKms(format!(
                    "Sign failed for key {}: {}",
                    self.key_id,
                    DisplayErrorContext(&e)
                ))
            })?;

        Ok(response
            .signature()
            .ok_or_else(|| {
                AppleCodesignError::AwsKms("KMS Sign response missing signature".into())
            })?
            .as_ref()
            .to_vec())
    }

    /// Sign an arbitrary message by hashing it locally and signing the digest in KMS.
    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, AppleCodesignError> {
        let algorithm = self.signing_algorithm_spec()?;
        let digest = DigestAlgorithm::Sha256.digest_data(message);

        // For RSASSA_PKCS1_V1_5_SHA_256 with MessageType=DIGEST, KMS performs
        // the EMSA-PKCS1-v1_5 encoding (including the DigestInfo) itself.
        // For ECDSA_SHA_256, KMS returns an ASN.1 DER-encoded signature, which
        // is the encoding expected everywhere in this crate.
        self.kms_sign_digest(digest, algorithm)
    }

    /// The X.509 certificate paired with the KMS key, if any.
    pub fn certificate(&self) -> Option<&CapturedX509Certificate> {
        self.certificate.as_ref()
    }

    /// The KMS key ID, key ARN, or alias this signing key uses.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl Signer<Signature> for AwsKmsPrivateKey {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        let signature = self
            .sign_message(message)
            .map_err(signature::Error::from_source)?;

        Ok(Signature::from(signature))
    }
}

impl KeyInfoSigner for AwsKmsPrivateKey {}

impl Sign for AwsKmsPrivateKey {
    fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError> {
        let algorithm = self.signature_algorithm()?;

        let signature = self
            .sign_message(message)
            .map_err(|e| X509CertificateError::Other(format!("AWS KMS signing error: {e}")))?;

        Ok((signature, algorithm))
    }

    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        Some(self.key_algorithm)
    }

    fn public_key_data(&self) -> Bytes {
        self.public_key_data.clone()
    }

    fn signature_algorithm(&self) -> Result<SignatureAlgorithm, X509CertificateError> {
        match self.key_algorithm {
            KeyAlgorithm::Rsa => Ok(SignatureAlgorithm::RsaSha256),
            KeyAlgorithm::Ecdsa(_) => Ok(SignatureAlgorithm::EcdsaSha256),
            algorithm => Err(X509CertificateError::UnknownSignatureAlgorithm(format!(
                "unsupported key algorithm for AWS KMS signing: {algorithm:?}"
            ))),
        }
    }

    fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>> {
        // KMS never exposes private key material.
        None
    }

    fn rsa_primes(
        &self,
    ) -> Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, X509CertificateError> {
        // KMS never exposes private key material.
        Ok(None)
    }
}

impl PublicKeyPeerDecrypt for AwsKmsPrivateKey {
    fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, RemoteSignError> {
        warn!("AWS KMS signing keys cannot be used for remote signing session decryption");

        Err(RemoteSignError::Crypto(
            "decryption via AWS KMS signing keys is not supported".into(),
        ))
    }
}

impl PrivateKey for AwsKmsPrivateKey {
    fn as_key_info_signer(&self) -> &dyn KeyInfoSigner {
        self
    }

    fn to_public_key_peer_decrypt(
        &self,
    ) -> Result<Box<dyn PublicKeyPeerDecrypt>, AppleCodesignError> {
        Ok(Box::new(self.clone()))
    }

    fn finish(&self) -> Result<(), AppleCodesignError> {
        Ok(())
    }
}
