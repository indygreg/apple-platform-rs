use {
    crate::{
        cryptography::{DigestType, PrivateKey},
        remote_signing::{session_negotiation::PublicKeyPeerDecrypt, RemoteSignError},
        AppleCodesignError,
    },
    bcder::{encode::Values, OctetString},
    bytes::Bytes,
    cryptoki::{
        context::{CInitializeArgs, CInitializeFlags, Pkcs11},
        mechanism::{Mechanism, MechanismType},
        object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
        session::UserType,
        types::AuthPin,
    },
    log::{info, warn},
    signature::Signer,
    std::{collections::HashMap, path::PathBuf, sync::Mutex},
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
    /// Logged in session, opened on first use and reused for all subsequent signing operations.
    ///
    /// Signing an entity can require multiple signatures (e.g. one per architecture of a universal
    /// Mach-O binary). Initializing the library and logging in again for each of them fails with
    /// CKR_USER_ALREADY_LOGGED_IN (or worse) on tokens that keep the login state.
    session: Mutex<Option<cryptoki::session::Session>>,
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
    ) -> Self {
        Self {
            library_path,
            slot_id,
            key_reference,
            pin,
            certificate,
            session: Mutex::new(None),
        }
    }

    pub fn new_with_label(
        library_path: PathBuf,
        slot_id: u64,
        key_label: String,
        pin: Option<String>,
        certificate: CapturedX509Certificate,
    ) -> Self {
        Self {
            library_path,
            slot_id,
            key_reference: KeyReference::Label(key_label),
            pin,
            certificate,
            session: Mutex::new(None),
        }
    }

    pub fn new_with_id(
        library_path: PathBuf,
        slot_id: u64,
        key_id: String,
        pin: Option<String>,
        certificate: CapturedX509Certificate,
    ) -> Self {
        Self {
            library_path,
            slot_id,
            key_reference: KeyReference::Id(key_id),
            pin,
            certificate,
            session: Mutex::new(None),
        }
    }

    pub fn new_from_certificate(
        library_path: PathBuf,
        slot_id: u64,
        pin: Option<String>,
        certificate: CapturedX509Certificate,
    ) -> Self {
        Self {
            library_path,
            slot_id,
            key_reference: KeyReference::FromCertificate,
            pin,
            certificate,
            session: Mutex::new(None),
        }
    }

    fn with_session<T, F>(&self, f: F) -> Result<T, AppleCodesignError>
    where
        F: FnOnce(&cryptoki::session::Session) -> Result<T, AppleCodesignError>,
    {
        let mut session = self
            .session
            .lock()
            .map_err(|_| AppleCodesignError::Pkcs11Error("PKCS11 session lock poisoned".into()))?;

        if session.is_none() {
            *session = Some(self.open_session()?);
        }

        // The session (and with it the library) is closed when the key is dropped
        f(session.as_ref().expect("session was opened above"))
    }

    fn open_session(&self) -> Result<cryptoki::session::Session, AppleCodesignError> {
        let pkcs11 = Pkcs11::new(&self.library_path)?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

        let slots = pkcs11.get_slots_with_token()?;
        let slot = slots
            .into_iter()
            .find(|s| s.id() == self.slot_id)
            .ok_or_else(|| {
                AppleCodesignError::Pkcs11Error(format!("PKCS11 slot {} not found", self.slot_id))
            })?;

        let session = pkcs11.open_rw_session(slot)?;

        if let Some(pin) = &self.pin {
            session.login(UserType::User, Some(&AuthPin::new(pin.clone().into())))?;
        }

        Ok(session)
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
            session: Mutex::new(None),
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

        let signature_bytes = match mechanism {
            // CKM_ECDSA returns the raw concatenation r || s, but X.509 and CMS expect a DER
            // encoded Ecdsa-Sig-Value (RFC 3279).
            MechanismType::ECDSA => ecdsa_raw_signature_to_der(&signature_bytes)
                .map_err(signature::Error::from_source)?,
            _ => signature_bytes,
        };

        Ok(Signature::from(signature_bytes))
    }
}

/// Converts a raw ECDSA signature (r || s, both of the same length) into a DER encoded
/// `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`.
fn ecdsa_raw_signature_to_der(raw: &[u8]) -> Result<Vec<u8>, AppleCodesignError> {
    if raw.is_empty() || raw.len() % 2 != 0 {
        return Err(AppleCodesignError::Pkcs11Error(format!(
            "unexpected length of raw ECDSA signature: {}",
            raw.len()
        )));
    }

    let (r, s) = raw.split_at(raw.len() / 2);

    let mut content = der_unsigned_integer(r);
    content.extend(der_unsigned_integer(s));

    let mut der = vec![0x30];
    der.extend(der_length(content.len()));
    der.extend(content);

    Ok(der)
}

fn der_unsigned_integer(value: &[u8]) -> Vec<u8> {
    let first_non_zero = value.iter().position(|b| *b != 0).unwrap_or(value.len());
    let mut bytes = value[first_non_zero..].to_vec();

    // INTEGER is signed, so positive values with the high bit set need a leading zero byte
    if bytes.first().map_or(true, |b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }

    let mut der = vec![0x02];
    der.extend(der_length(bytes.len()));
    der.extend(bytes);
    der
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        vec![length as u8]
    } else {
        let bytes = length.to_be_bytes();
        let first_non_zero = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut der = vec![0x80 | (bytes.len() - first_non_zero) as u8];
        der.extend(&bytes[first_non_zero..]);
        der
    }
}

impl KeyInfoSigner for Pkcs11PrivateKey {}

impl Sign for Pkcs11PrivateKey {
    fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError> {
        let algorithm = self.signature_algorithm()?;

        let signature = self
            .try_sign(message)
            .map_err(|e| X509CertificateError::Other(format!("PKCS11 signing error: {}", e)))?;

        Ok((signature.as_ref().to_vec(), algorithm))
    }

    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        self.certificate.key_algorithm()
    }

    fn public_key_data(&self) -> Bytes {
        self.certificate.public_key_data()
    }

    fn signature_algorithm(&self) -> Result<SignatureAlgorithm, X509CertificateError> {
        // The signature algorithm of the certificate is the one its issuer used, the signatures
        // created here always use SHA-256 with the algorithm of the certificate's key (see try_sign).
        match self.certificate.key_algorithm() {
            Some(KeyAlgorithm::Rsa) => Ok(SignatureAlgorithm::RsaSha256),
            Some(KeyAlgorithm::Ecdsa(_)) => Ok(SignatureAlgorithm::EcdsaSha256),
            other => Err(X509CertificateError::UnknownSignatureAlgorithm(format!(
                "{:?}",
                other
            ))),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_raw_signature_to_der_encodes_sequence_of_integers() {
        let raw = [[0x01u8; 32], [0x02u8; 32]].concat();

        let der = ecdsa_raw_signature_to_der(&raw).unwrap();

        let mut expected = vec![0x30, 68, 0x02, 32];
        expected.extend([0x01u8; 32]);
        expected.extend([0x02, 32]);
        expected.extend([0x02u8; 32]);
        assert_eq!(der, expected);
    }

    #[test]
    fn ecdsa_raw_signature_to_der_strips_leading_zeros_and_keeps_integers_positive() {
        let mut r = vec![0x00, 0x00, 0x7f];
        r.extend([0xaa; 29]);
        let mut s = vec![0x80];
        s.extend([0xbb; 31]);
        let raw = [r, s].concat();

        let der = ecdsa_raw_signature_to_der(&raw).unwrap();

        let mut expected = vec![0x30, 67, 0x02, 30, 0x7f];
        expected.extend([0xaa; 29]);
        expected.extend([0x02, 33, 0x00, 0x80]);
        expected.extend([0xbb; 31]);
        assert_eq!(der, expected);
    }

    #[test]
    fn ecdsa_raw_signature_to_der_uses_long_form_length_for_p521() {
        let raw = [[0x01u8; 66], [0x01u8; 66]].concat();

        let der = ecdsa_raw_signature_to_der(&raw).unwrap();

        assert_eq!(&der[..3], &[0x30, 0x81, 136]);
    }

    #[test]
    fn ecdsa_raw_signature_to_der_rejects_odd_length() {
        assert!(ecdsa_raw_signature_to_der(&[0x01, 0x02, 0x03]).is_err());
    }
}
