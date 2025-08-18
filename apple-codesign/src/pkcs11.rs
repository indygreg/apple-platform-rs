use {
    crate::{
        cryptography::{DigestType, PrivateKey},
        remote_signing::{session_negotiation::PublicKeyPeerDecrypt, RemoteSignError},
        AppleCodesignError,
    },
    bcder::{encode::Values, OctetString},
    bytes::Bytes,
    cryptoki::{
        context::{CInitializeArgs, Pkcs11},
        mechanism::{Mechanism, MechanismType},
        object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
        session::UserType,
        types::AuthPin,
    },
    log::{info, warn},
    signature::Signer,
    std::{collections::HashMap, path::PathBuf},
    x509_certificate::{
        rfc3447::DigestInfo, CapturedX509Certificate, DigestAlgorithm, KeyAlgorithm, KeyInfoSigner,
        Sign, Signature, SignatureAlgorithm, X509CertificateError,
    },
    zeroize::Zeroizing,
};

pub struct Pkcs11PrivateKey {
    library_path: PathBuf,
    slot_id: u64,
    key_reference: KeyReference,
    pin: Option<String>,
    certificate: CapturedX509Certificate,
}

/// Reference to a private key in the PKCS11 token
#[derive(Clone, Debug)]
pub enum KeyReference {
    /// Direct object handle (for traditional PKCS11 tokens)
    Handle(ObjectHandle),
    /// Key identified by CKA_LABEL attribute
    Label(String),
    /// Key identified by CKA_ID attribute
    Id(String),
    /// Automatically discover key based on certificate
    FromCertificate,
}

impl Pkcs11PrivateKey {
    pub fn new(
        library_path: PathBuf,
        slot_id: u64,
        key_reference: KeyReference,
        pin: Option<String>,
        certificate: CapturedX509Certificate,
    ) -> Result<Self, AppleCodesignError> {
        Ok(Self {
            library_path,
            slot_id,
            key_reference,
            pin,
            certificate,
        })
    }

    pub fn new_with_label(
        library_path: PathBuf,
        slot_id: u64,
        key_label: String,
        pin: Option<String>,
        certificate: CapturedX509Certificate,
    ) -> Result<Self, AppleCodesignError> {
        Ok(Self {
            library_path,
            slot_id,
            key_reference: KeyReference::Label(key_label),
            pin,
            certificate,
        })
    }

    pub fn new_with_id(
        library_path: PathBuf,
        slot_id: u64,
        key_id: String,
        pin: Option<String>,
        certificate: CapturedX509Certificate,
    ) -> Result<Self, AppleCodesignError> {
        Ok(Self {
            library_path,
            slot_id,
            key_reference: KeyReference::Id(key_id),
            pin,
            certificate,
        })
    }

    pub fn new_from_certificate(
        library_path: PathBuf,
        slot_id: u64,
        pin: Option<String>,
        certificate: CapturedX509Certificate,
    ) -> Result<Self, AppleCodesignError> {
        Ok(Self {
            library_path,
            slot_id,
            key_reference: KeyReference::FromCertificate,
            pin,
            certificate,
        })
    }

    fn with_session<T, F>(&self, f: F) -> Result<T, AppleCodesignError>
    where
        F: FnOnce(&cryptoki::session::Session) -> Result<T, AppleCodesignError>,
    {
        let pkcs11 = Pkcs11::new(&self.library_path)?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .or_else(|e| match e {
                cryptoki::error::Error::AlreadyInitialized => Ok(()),
                _ => Err(e),
            })?;

        let slots = pkcs11.get_slots_with_token()?;
        let slot = slots
            .into_iter()
            .find(|s| s.id() == self.slot_id)
            .ok_or_else(|| {
                AppleCodesignError::Pkcs11Error(format!("PKCS11 slot {} not found", self.slot_id))
            })?;

        let session = pkcs11.open_rw_session(slot)?;

        if let Some(pin) = &self.pin {
            session.login(UserType::User, Some(&AuthPin::new(pin.clone())))?;
        }

        let result = f(&session)?;

        // Session will be automatically closed when dropped
        Ok(result)
    }

    fn sign_data_with_mechanism(
        &self,
        data: &[u8],
        mechanism: MechanismType,
    ) -> Result<Vec<u8>, AppleCodesignError> {
        let mech = match mechanism {
            MechanismType::ECDSA => Mechanism::Ecdsa,
            MechanismType::RSA_PKCS => Mechanism::RsaPkcs,
            MechanismType::RSA_PKCS_PSS => {
                warn!("RSA PSS requested but using basic RSA PKCS for simplicity");
                Mechanism::RsaPkcs
            }
            _ => {
                return Err(AppleCodesignError::Pkcs11Error(format!(
                    "Unsupported mechanism: {:?}",
                    mechanism
                )))
            }
        };
        self.with_session(|session| {
            // Find the private key for signing
            let key_handle = match &self.key_reference {
                KeyReference::Handle(handle) => *handle,
                KeyReference::Label(label) => self.find_private_key_by_label(session, label)?,
                KeyReference::Id(id) => self.find_private_key_by_id(session, id)?,
                KeyReference::FromCertificate => self.find_private_key_for_certificate(session)?,
            };

            let signature = session.sign(&mech, key_handle, data)?;
            Ok(signature)
        })
    }

    fn find_private_key_by_label(
        &self,
        session: &cryptoki::session::Session,
        label: &str,
    ) -> Result<ObjectHandle, AppleCodesignError> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Sign(true),
        ];

        let objects = session.find_objects(&template)?;

        if objects.is_empty() {
            return Err(AppleCodesignError::Pkcs11Error(format!(
                "private key with CKA_LABEL '{}' not found in PKCS11 token",
                label
            )));
        }

        Ok(objects[0])
    }

    fn find_private_key_by_id(
        &self,
        session: &cryptoki::session::Session,
        id: &str,
    ) -> Result<ObjectHandle, AppleCodesignError> {
        // Handle potential hex-encoding that some PKCS11 tools use
        let id_bytes = hex::decode(id).unwrap_or_else(|_| id.as_bytes().to_vec());

        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(id_bytes),
            Attribute::Sign(true),
        ];

        let objects = session.find_objects(&template)?;

        if objects.is_empty() {
            return Err(AppleCodesignError::Pkcs11Error(format!(
                "private key with CKA_ID '{}' not found in PKCS11 token",
                id
            )));
        }

        Ok(objects[0])
    }

    fn find_private_key_for_certificate(
        &self,
        session: &cryptoki::session::Session,
    ) -> Result<ObjectHandle, AppleCodesignError> {
        // Strategy 1: Try to find a private key with the same CKA_LABEL as the certificate
        if let Ok(cert_attrs) = self.get_certificate_attributes(session) {
            if let Some(cert_label) = cert_attrs.get(&AttributeType::Label) {
                if let Attribute::Label(label_bytes) = cert_label {
                    let label = String::from_utf8_lossy(label_bytes);
                    if let Ok(key_handle) = self.find_private_key_by_label(session, &label) {
                        info!("found private key using certificate's CKA_LABEL: {}", label);
                        return Ok(key_handle);
                    }
                }
            }

            // Strategy 2: Try to find a private key with the same CKA_ID as the certificate
            if let Some(cert_id) = cert_attrs.get(&AttributeType::Id) {
                if let Attribute::Id(id_bytes) = cert_id {
                    let id = String::from_utf8_lossy(id_bytes);
                    if let Ok(key_handle) = self.find_private_key_by_id(session, &id) {
                        info!("found private key using certificate's CKA_ID");
                        return Ok(key_handle);
                    }
                }
            }
        }

        // Strategy 3: Find any signing-capable private key
        // This works with simple PKCS11 setups that have only one signing key
        warn!("certificate not found in PKCS11 token or no matching key attributes, searching for any signing-capable private key");

        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Sign(true),
        ];

        let objects = session.find_objects(&template)?;

        if objects.is_empty() {
            return Err(AppleCodesignError::Pkcs11Error(
                "no signing-capable private key found in PKCS11 token".into(),
            ));
        }

        if objects.len() > 1 {
            warn!("multiple private keys found, using the first one. Consider specifying --pkcs11-key-label or --pkcs11-key-id for precision");
        }

        Ok(objects[0])
    }

    fn get_certificate_attributes(
        &self,
        session: &cryptoki::session::Session,
    ) -> Result<HashMap<AttributeType, Attribute>, AppleCodesignError> {
        // Try to find the certificate in the token by its DER content
        let template = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Value(self.certificate.constructed_data().to_vec()),
        ];

        let objects = session.find_objects(&template)?;

        if objects.is_empty() {
            // Certificate not found in token--this is OK if loaded from file
            return Err(AppleCodesignError::Pkcs11Error(
                "certificate not found in PKCS11 token (normal if certificate was loaded from file)".into()
            ));
        }

        let cert_handle = objects[0];
        let attrs =
            session.get_attributes(cert_handle, &[AttributeType::Label, AttributeType::Id])?;

        let mut attr_map = HashMap::new();
        for attr in attrs {
            attr_map.insert(attr.attribute_type(), attr);
        }

        Ok(attr_map)
    }

    pub fn certificate(&self) -> &CapturedX509Certificate {
        &self.certificate
    }

    pub fn slot_id(&self) -> u64 {
        self.slot_id
    }

    pub fn key_reference(&self) -> &KeyReference {
        &self.key_reference
    }
}

impl Clone for Pkcs11PrivateKey {
    fn clone(&self) -> Self {
        Self {
            library_path: self.library_path.clone(),
            slot_id: self.slot_id,
            key_reference: self.key_reference.clone(),
            pin: self.pin.clone(),
            certificate: self.certificate.clone(),
        }
    }
}

impl Signer<Signature> for Pkcs11PrivateKey {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        // Use the certificate's key algorithm, not signature algorithm (which is from the CA)
        let key_algorithm = self.certificate.key_algorithm().ok_or_else(|| {
            signature::Error::from_source("Cannot determine key algorithm from certificate")
        })?;

        info!("Certificate key algorithm: {:?}", key_algorithm);

        let (mechanism, input) = match key_algorithm {
            KeyAlgorithm::Ecdsa(_) => {
                let hashed_data = DigestType::Sha256
                    .digest_data(message)
                    .map_err(signature::Error::from_source)?;
                (MechanismType::ECDSA, hashed_data)
            }
            KeyAlgorithm::Rsa => {
                // Some PKCS11 modules, such as Google Cloud HSM, claim to support SHA256_RSA_PKCS
                // but attempting to use it returns "Unsupported mechanism: MechanismType { val: 64 }".
                // Use the least common denominator with RSA_PKCS.
                let digest = DigestAlgorithm::Sha256.digest_data(message);

                // Unfortunately we can't use x509_certificate::rsa_pkcs1_encode() here because it
                // implements CKM_RSA_X_509 instead of CKM_RSA_PKCS.
                // CKM_RSA_X_509 implements the full padding procedure described in https://tools.ietf.org/html/rfc3447#section-9.2:
                //
                // For 2048-bit RSA (256 bytes total):
                // Byte 0:     0x00                    (header)
                // Byte 1:     0x01                    (signature block type)
                // Bytes 2-X:  0xFF 0xFF 0xFF ...      (padding, ~205 bytes)
                // Byte X+1:   0x00                    (null terminator)
                // Bytes X+2+: 30 31 30 0d ... hash    (DigestInfo, ~51 bytes)
                //
                // CKM_RSA_PKCS expects the input to be the DigestInfo, with the header, block type, and
                // padding omitted.
                let digest_info = DigestInfo {
                    algorithm: DigestAlgorithm::Sha256.into(),
                    digest: OctetString::new(digest.into()),
                };

                let mut digest_info_der = vec![];
                digest_info
                    .write_encoded(bcder::Mode::Der, &mut digest_info_der)
                    .map_err(signature::Error::from_source)?;

                (MechanismType::RSA_PKCS, digest_info_der)
            }
            _ => {
                return Err(signature::Error::from_source(format!(
                    "Unsupported key algorithm for PKCS11: {:?}",
                    key_algorithm
                )))
            }
        };

        let signature_bytes = self
            .sign_data_with_mechanism(&input, mechanism)
            .map_err(signature::Error::from_source)?;

        Ok(Signature::from(signature_bytes))
    }
}

impl KeyInfoSigner for Pkcs11PrivateKey {}

impl Sign for Pkcs11PrivateKey {
    fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError> {
        let algorithm = self.signature_algorithm()?;

        let mechanism = match algorithm {
            SignatureAlgorithm::EcdsaSha256 => MechanismType::ECDSA,
            SignatureAlgorithm::RsaSha256 => MechanismType::RSA_PKCS,
            _ => {
                return Err(X509CertificateError::Other(format!(
                    "Unsupported signature algorithm for PKCS11: {:?}",
                    algorithm
                )))
            }
        };

        let signature = self
            .sign_data_with_mechanism(message, mechanism)
            .map_err(|e| X509CertificateError::Other(format!("PKCS11 signing error: {}", e)))?;

        Ok((signature, algorithm))
    }

    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        self.certificate.key_algorithm()
    }

    fn public_key_data(&self) -> Bytes {
        self.certificate.public_key_data()
    }

    fn signature_algorithm(&self) -> Result<SignatureAlgorithm, X509CertificateError> {
        self.certificate.signature_algorithm().ok_or(
            X509CertificateError::UnknownSignatureAlgorithm(format!(
                "{:?}",
                self.certificate.signature_algorithm_oid()
            )),
        )
    }

    fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>> {
        // PKCS11 providers never expose private key data
        None
    }

    fn rsa_primes(
        &self,
    ) -> Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, X509CertificateError> {
        // PKCS11 providers never expose RSA prime factors
        Ok(None)
    }
}

impl PublicKeyPeerDecrypt for Pkcs11PrivateKey {
    fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, RemoteSignError> {
        // For RSA keys, we could potentially support decryption
        match self.certificate.key_algorithm() {
            Some(KeyAlgorithm::Rsa) => {
                // Could implement RSA decryption here if needed
                Err(RemoteSignError::Crypto(
                    "RSA decryption via PKCS11 not yet implemented".into(),
                ))
            }
            _ => Err(RemoteSignError::Crypto(
                "decryption only supported for RSA keys".into(),
            )),
        }
    }
}

impl PrivateKey for Pkcs11PrivateKey {
    fn as_key_info_signer(&self) -> &dyn KeyInfoSigner {
        self
    }

    fn to_public_key_peer_decrypt(
        &self,
    ) -> Result<Box<dyn PublicKeyPeerDecrypt>, AppleCodesignError> {
        Ok(Box::new(self.clone()))
    }

    fn finish(&self) -> Result<(), AppleCodesignError> {
        // Could implement cleanup logic here if needed
        // For now, PKCS11 sessions are cleaned up automatically
        Ok(())
    }
}

// Convert PKCS11 errors to AppleCodesignError
impl From<cryptoki::error::Error> for AppleCodesignError {
    fn from(err: cryptoki::error::Error) -> Self {
        AppleCodesignError::Pkcs11Error(format!("PKCS11 error: {}", err))
    }
}
