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
        error::RvError,
        mechanism::{Mechanism, MechanismType},
        object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
        session::UserType,
        types::AuthPin,
    },
    log::{info, warn},
    signature::Signer,
    std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::{LazyLock, Mutex, MutexGuard},
    },
    x509_certificate::{
        rfc3447::DigestInfo, CapturedX509Certificate, DigestAlgorithm, KeyAlgorithm, KeyInfoSigner,
        Sign, Signature, SignatureAlgorithm, X509CertificateError,
    },
    zeroize::Zeroizing,
};

/// A PKCS#11 module context plus how it came to be initialized.
struct ModuleContext {
    context: Pkcs11,

    /// Whether the `C_Initialize` backing this context was issued by us.
    ///
    /// False when the module reported it was already initialized, in which case something
    /// else owns that initialization and we must not finalize it out from under it.
    initialized_here: bool,
}

/// Process-wide registry of initialized PKCS#11 module contexts, keyed by library path.
///
/// A PKCS#11 module is initialized once per process: `C_Initialize` on a module that is
/// already initialized fails with `CKR_CRYPTOKI_ALREADY_INITIALIZED`. Certificate resolution
/// and every signing operation each need a context, so contexts are created once and shared
/// rather than created on demand. Dropping a [Pkcs11] does not finalize the module (cryptoki
/// has no finalize-on-drop), so creating them on demand leaves the module initialized and
/// makes every subsequent initialization fail.
static MODULE_CONTEXTS: LazyLock<Mutex<HashMap<PathBuf, ModuleContext>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Key a module by its resolved path so different spellings of the same library share a context.
fn module_key(library_path: &Path) -> PathBuf {
    std::fs::canonicalize(library_path).unwrap_or_else(|_| library_path.to_path_buf())
}

fn module_contexts() -> MutexGuard<'static, HashMap<PathBuf, ModuleContext>> {
    // The registry has no invariant that a panic could break, so a poisoned lock is usable.
    MODULE_CONTEXTS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Obtain an initialized context for a PKCS#11 module, initializing it on first use.
///
/// Repeated calls for the same library return the same context.
pub(crate) fn initialized_module(library_path: &Path) -> Result<Pkcs11, AppleCodesignError> {
    let key = module_key(library_path);
    let mut contexts = module_contexts();

    if let Some(existing) = contexts.get(&key) {
        return Ok(existing.context.clone());
    }

    let context = Pkcs11::new(library_path)?;

    let initialized_here =
        match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) => {
                info!("initialized PKCS11 library: {}", library_path.display());
                true
            }
            // Something else in this process already initialized the module. That
            // initialization is usable as-is, so adopt it instead of failing.
            Err(cryptoki::error::Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {
                warn!(
                    "PKCS11 library {} is already initialized; reusing that initialization",
                    library_path.display()
                );
                false
            }
            Err(e) => return Err(e.into()),
        };

    contexts.insert(
        key,
        ModuleContext {
            context: context.clone(),
            initialized_here,
        },
    );

    Ok(context)
}

/// Finalize a PKCS#11 module and forget its context.
///
/// Does nothing when the module is unknown or when its initialization is owned by something
/// else. A later [initialized_module] call for the same library initializes it again.
///
/// There is no use counting: the first caller to finalize a library finalizes it for every
/// [Pkcs11PrivateKey] sharing it. The CLI resolves at most one private key, and the
/// re-initialization above makes that recoverable, so this only matters to embedders
/// driving several keys on one module.
pub(crate) fn finalize_module(library_path: &Path) -> Result<(), AppleCodesignError> {
    let key = module_key(library_path);
    let mut contexts = module_contexts();

    let Some(entry) = contexts.remove(&key) else {
        return Ok(());
    };

    if !entry.initialized_here {
        return Ok(());
    }

    // finalize() consumes the context; clone so `entry` survives a failure.
    if let Err(e) = entry.context.clone().finalize() {
        // The module is most likely still initialized and still ours, so keep the entry
        // rather than orphaning a module nothing can finalize later.
        contexts.insert(key, entry);
        return Err(e.into());
    }

    info!("finalized PKCS11 library: {}", library_path.display());

    Ok(())
}

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
    ) -> Self {
        Self {
            library_path,
            slot_id,
            key_reference,
            pin,
            certificate,
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
        }
    }

    fn with_session<T, F>(&self, f: F) -> Result<T, AppleCodesignError>
    where
        F: FnOnce(&cryptoki::session::Session) -> Result<T, AppleCodesignError>,
    {
        let pkcs11 = initialized_module(&self.library_path)?;

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
        // Sessions close on drop. The module context outlives them and is finalized here so
        // the process pairs its C_Initialize with a C_Finalize. A module that refuses to
        // finalize is not a reason to fail a signing run that already wrote its output.
        if let Err(e) = finalize_module(&self.library_path) {
            warn!("failed to finalize PKCS11 library: {}", e);
        }

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
mod test {
    use super::*;

    /// Path to a PKCS#11 module to exercise, if the environment provides one.
    ///
    /// Tests below need a real, spec compliant module. Point this at one to run them, e.g.
    /// `APPLE_CODESIGN_TEST_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so`. The module
    /// does not need an initialized token; only initialization and slot enumeration are
    /// exercised.
    ///
    /// The name deliberately avoids the `RCODESIGN_` prefix, which the CLI consumes as
    /// configuration and rejects for unknown keys.
    fn test_library() -> Option<PathBuf> {
        let path = PathBuf::from(std::env::var_os("APPLE_CODESIGN_TEST_PKCS11_LIBRARY")?);

        if path.exists() {
            Some(path)
        } else {
            panic!(
                "APPLE_CODESIGN_TEST_PKCS11_LIBRARY does not exist: {}",
                path.display()
            );
        }
    }

    /// Walks the full module lifecycle in one test because the registry is process global.
    #[test]
    fn module_context_is_shared_and_finalized() {
        let Some(library) = test_library() else {
            eprintln!("skipping: APPLE_CODESIGN_TEST_PKCS11_LIBRARY is not set");
            return;
        };

        // Stand in for a module the loader keeps resident: it is already initialized by
        // the time we ask for a context. Adopting that initialization is what keeps this
        // from failing with CKR_CRYPTOKI_ALREADY_INITIALIZED.
        let foreign = Pkcs11::new(&library).unwrap();
        foreign
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .unwrap();

        let adopted = initialized_module(&library).expect("adopting an initialized module");
        adopted
            .get_slots_with_token()
            .expect("adopted context works");

        // Every later request reuses that context rather than initializing a second time.
        let reused = initialized_module(&library).expect("reusing the adopted module");
        reused.get_slots_with_token().expect("reused context works");

        {
            let contexts = module_contexts();
            assert_eq!(contexts.len(), 1, "both requests share one registry entry");
            assert!(
                !contexts.values().next().unwrap().initialized_here,
                "an adopted initialization is not ours to finalize"
            );
        }

        // The initialization is not ours, so finalizing must leave it alone.
        finalize_module(&library).expect("finalize skips a foreign initialization");
        foreign
            .get_slots_with_token()
            .expect("foreign initialization survived");
        foreign.finalize().unwrap();

        // Nothing holds the module now, so the next context owns its initialization and
        // finalizing it is what pairs our C_Initialize with a C_Finalize.
        let owned = initialized_module(&library).expect("initializing a finalized module");
        owned.get_slots_with_token().expect("owned context works");

        {
            let contexts = module_contexts();
            assert!(
                contexts.values().next().unwrap().initialized_here,
                "we performed this initialization"
            );
        }

        finalize_module(&library).expect("finalizing our own initialization");
        assert!(module_contexts().is_empty(), "finalize forgets the context");

        // Finalizing forgets the context, so the module can be initialized again.
        initialized_module(&library).expect("initializing again after finalize");
        finalize_module(&library).unwrap();

        // Finalizing a module we know nothing about is a no-op.
        finalize_module(&library).expect("finalize is idempotent");
    }
}
