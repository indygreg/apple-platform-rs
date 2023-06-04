// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{
        certificate::{
            create_self_signed_code_signing_certificate, AppleCertificate, CertificateProfile,
        },
        code_directory::{CodeDirectoryBlob, CodeSignatureFlags},
        code_requirement::CodeRequirements,
        cryptography::{parse_pfx_data, InMemoryPrivateKey, PrivateKey},
        embedded_signature::{Blob, CodeSigningSlot, DigestType, RequirementSetBlob},
        error::AppleCodesignError,
        macho::MachFile,
        reader::SignatureReader,
        remote_signing::{
            session_negotiation::{
                create_session_joiner, PublicKeyInitiator, SessionInitiatePeer, SessionJoinState,
                SharedSecretInitiator,
            },
            RemoteSignError, UnjoinedSigningClient,
        },
        signing::UnifiedSigner,
        signing_settings::{SettingsScope, SigningSettings},
    },
    base64::{engine::general_purpose::STANDARD as STANDARD_ENGINE, Engine},
    clap::{ArgAction, Args, Parser, Subcommand},
    cryptographic_message_syntax::SignedData,
    difference::{Changeset, Difference},
    log::{error, warn, LevelFilter},
    spki::EncodePublicKey,
    std::{io::Write, path::PathBuf, str::FromStr},
    x509_certificate::{CapturedX509Certificate, EcdsaCurve, KeyAlgorithm, X509CertificateBuilder},
};

#[cfg(feature = "notarize")]
use crate::notarization::Notarizer;

#[cfg(feature = "yubikey")]
use {
    crate::yubikey::YubiKey,
    yubikey::{PinPolicy, TouchPolicy},
};

#[cfg(target_os = "macos")]
use crate::macos::{
    keychain_find_code_signing_certificates, macos_keychain_find_certificate_chain, KeychainDomain,
};

const EXTRACT_ABOUT: &str = "\
Extract code signature data from a Mach-O binary.

Given the path to a Mach-O binary (including fat/universal) binaries, this
command will parse and print requested data to stdout.

The --data argument controls which data to extract and how to print it.
Possible values are:

blobs
   Low-level information on the records in the embedded code signature.
cms-info
   Print important information about the CMS data structure.
cms-pem
   Like cms-raw except it prints PEM encoded data, which is ASCII and
   safe to print to terminals.
cms-raw
   Print the payload of the CMS blob. This should be well-formed BER
   encoded ASN.1 data. (This will print binary to stdout.)
cms
   Print the ASN.1 decoded CMS data.
code-directory-raw
   Raw binary data composing the code directory data structure.
code-directory
   Information on the main code directory data structure.
code-directory-serialized
   Reserialize the parsed code directory, parse it again, and then print
   it like `code-directory` would.
code-directory-serialized-raw
   Reserialize the parsed code directory and emit its binary. Useful
   for comparing round-tripping of code directory data.
linkedit-info
   Information about the __LINKEDIT Mach-O segment in the binary.
linkedit-segment-raw
   Complete content of the __LINKEDIT Mach-O segment as binary.
macho-load-commands
   Print information about mach-o load commands in the binary.
macho-segments
   Print information about mach-o segments in the binary.
macho-target
   Print mach-o targeting info (platform and OS/SDK versions).
requirements-raw
   Raw binary data composing the requirements blob/slot.
requirements
   Parsed code requirement statement/expression.
requirements-rust
   Dump the internal Rust data structures representing the requirements
   expressions.
requirements-serialized
   Reserialize the code requirements blob, parse it again, and then
   print it like `requirements` would.
requirements-serialized-raw
   Reserialize the code requirements blob and emit its binary.
signature-raw
   Raw binary data composing the signature data embedded in the binary.
superblob
   The SuperBlob record and high-level details of embedded Blob
   records, including digests of every Blob.
";

const GENERATE_SELF_SIGNED_CERTIFICATE_ABOUT: &str = "\
Generate a self-signed certificate that can be used for code signing.

This command will generate a new key pair using the algorithm of choice
then create an X.509 certificate wrapper for it that is signed with the
just-generated private key. The created X.509 certificate has extensions
that mark it as appropriate for code signing.

Certificates generated with this command can be useful for local testing.
However, because it is a self-signed certificate and isn't signed by a
trusted certificate authority, Apple operating systems may refuse to
load binaries signed with it.

By default the command prints 2 PEM encoded blocks. One block is for the
X.509 public certificate. The other is for the PKCS#8 private key (which
can include the public key).

The `--pem-filename` argument can be specified to write the generated
certificate pair to a pair of files. The destination files will have
`.crt` and `.key` appended to the value provided.

When the certificate is written to a file, it isn't printed to stdout.
";

const PARSE_CODE_SIGNING_REQUIREMENT_ABOUT: &str = "\
Parse code signing requirement data into human readable text.

This command can be used to parse binary code signing requirement data and
print it in various formats.

The source input format is the binary code requirement serialization. This
is the format generated by Apple's `csreq` tool via `csreq -b`. The binary
data begins with header magic `0xfade0c00`.

The default output format is the Code Signing Requirement Language. But the
output format can be changed via the --format argument.

Our Code Signing Requirement Language output may differ from Apple's. For
example, `and` and `or` expressions always have their sub-expressions surrounded
by parentheses (e.g. `(a) and (b)` instead of `a and b`) and strings are always
quoted. The differences, however, should not matter to the parser or result
in a different binary serialization.
";

const SIGN_ABOUT: &str = "\
Adds code signatures to a signable entity.

This command can sign the following entities:

* A single Mach-O binary (specified by its file path)
* A bundle (specified by its directory path)
* A DMG disk image (specified by its path)
* A XAR archive (commonly a .pkg installer file)

If the input is Mach-O binary, it can be a single or multiple/fat/universal
Mach-O binary. If a fat binary is given, each Mach-O within that binary will
be signed.

If the input is a bundle, the bundle will be recursively signed. If the
bundle contains nested bundles or Mach-O binaries, those will be signed
automatically.

# Settings Scope

The following signing settings are global and apply to all signed entities:

* --digest
* --pem-source
* --team-name
* --timestamp-url

The following signing settings can be scoped so they only apply to certain
entities:

* --binary-identifier
* --code-requirements-path
* --code-resources-path
* --code-signature-flags
* --entitlements-xml-path
* --info-plist-path

Scoped settings take the form <value> or <scope>:<value>. If the 2nd form
is used, the string before the first colon is parsed as a \"scoping string\".
It can have the following values:

* `main` - Applies to the main entity being signed and all nested entities.
* `@<integer>` - e.g. `@0`. Applies to a Mach-O within a fat binary at the
  specified index. 0 means the first Mach-O in a fat binary.
* `@[cpu_type=<int>` - e.g. `@[cpu_type=7]`. Applies to a Mach-O within a fat
  binary targeting a numbered CPU architecture (using numeric constants
  as defined by Mach-O).
* `@[cpu_type=<string>` - e.g. `@[cpu_type=x86_64]`. Applies to a Mach-O within
  a fat binary targeting a CPU architecture identified by a string. See below
  for the list of recognized values.
* `<string>` - e.g. `path/to/file`. Applies to content at a given path. This
  should be the bundle-relative path to a Mach-O binary, a nested bundle, or
  a Mach-O binary within a nested bundle. If a nested bundle is referenced,
  settings apply to everything within that bundle.
* `<string>@<int>` - e.g. `path/to/file@0`. Applies to a Mach-O within a
  fat binary at the given path. If the path is to a bundle, the setting applies
  to all Mach-O binaries in that bundle.
* `<string>@[cpu_type=<int|string>]` e.g. `Contents/MacOS/binary@[cpu_type=7]`
  or `Contents/MacOS/binary@[cpu_type=arm64]`. Applies to a Mach-O within a
  fat binary targeting a CPU architecture identified by its integer constant
  or string name. If the path is to a bundle, the setting applies to all
  Mach-O binaries in that bundle.

The following named CPU architectures are recognized:

* arm
* arm64
* arm64_32
* x86_64

Signing will traverse into nested entities:

* A fat Mach-O binary will traverse into the multiple Mach-O binaries within.
* A bundle will traverse into nested bundles.
* A bundle will traverse non-code \"resource\" files and sign their digests.
* A bundle will traverse non-main Mach-O binaries and sign them, adding their
  metadata to the signed resources file.

# Bundle Signing Overrides Settings

When signing bundles, some settings specified on the command line will be
ignored. This is to ensure that the produced signing data is correct. The
settings ignored include (but may not be limited to):

* --binary-identifier for the main executable. The `CFBundleIdentifier` value
  from the bundle's `Info.plist` will be used instead.
* --code-resources-path. The code resources data will be computed automatically
  as part of signing the bundle.
* --info-plist-path. The `Info.plist` from the bundle will be used instead.
* --digest and --extra-digest

# Designated Code Requirements

When using Apple issued code signing certificates, we will attempt to apply
an appropriate designated requirement automatically during signing which
matches the behavior of what `codesign` would do. We do not yet support all
signing certificates and signing targets for this, however. So you may
need to provide your own requirements.

Designated code requirements can be specified via --code-requirements-path.

This file MUST contain a binary/compiled code requirements expression. We do
not (yet) support parsing the human-friendly code requirements DSL. A
binary/compiled file can be produced via Apple's `csreq` tool. e.g.
`csreq -r '=<expression>' -b /output/path`. If code requirements data is
specified, it will be parsed and displayed as part of signing to ensure it
is well-formed.

# Code Signing Key Pair

By default, the embedded code signature will only contain digests of the
binary and other important entities (such as entitlements and resources).
This is often referred to as \"ad-hoc\" signing.

To use a code signing key/certificate to derive a cryptographic signature,
you must specify a source certificate to use. This can be done in the following
ways:

* The --p12-file denotes the location to a PFX formatted file. These are
  often .pfx or .p12 files. A password is required to open these files.
  Specify one via --p12-password or --p12-password-file or enter a password
  when prompted.
* The --pem-source argument defines paths to files containing PEM encoded
  certificate/key data. (e.g. files with \"===== BEGIN CERTIFICATE =====\").
* The --source-source argument defines paths to files containiner DER
  encoded certificate/key data.
* The --keychain-domain and --keychain-fingerprint arguments can be used to
  load code signing certificates from macOS keychains. These arguments are
  ignored on non-macOS platforms.
* The --smartcard-slot argument defines the name of a slot in a connected
  smartcard device to read from. `9c` is common.
* Arguments beginning with --remote activate *remote signing mode* and can
  be used to delegate cryptographic signing operations to a separate machine.
  It is strongly advised to read the user documentation on remote signing
  mode at https://gregoryszorc.com/docs/apple-codesign/main/.

If you export a code signing certificate from the macOS keychain via the
`Keychain Access` application as a .p12 file, we should be able to read these
files via --p12-file.

When using --pem-source, certificates and public keys are parsed from
`BEGIN CERTIFICATE` and `BEGIN PRIVATE KEY` sections in the files.

The way certificate discovery works is that --p12-file is read followed by
all values to --pem-source. The seen signing keys and certificates are
collected. After collection, there must be 0 or 1 signing keys present, or
an error occurs. The first encountered public certificate is assigned
to be paired with the signing key. All remaining certificates are assumed
to constitute the CA issuing chain and will be added to the signature
data to facilitate validation.

If you are using an Apple-issued code signing certificate, we detect this
and automatically register the Apple CA certificate chain so it is included
in the digital signature. This matches the behavior of the `codesign` tool.

For best results, put your private key and its corresponding X.509 certificate
in a single file, either a PFX or PEM formatted file. Then add any additional
certificates constituting the signing chain in a separate PEM file.

When using a code signing key/certificate, a Time-Stamp Protocol server URL
can be specified via --timestamp-url. By default, Apple's server is used. The
special value \"none\" can disable using a timestamp server.

# Selecting What to Sign

By default, this command attempts to recursively sign everything in the source
path. This applies to:

* Bundles. If the specified bundle has nested bundles, those nested bundles
  will be signed automatically.

It is possible to exclude nested items from signing using --exclude. This
argument takes a glob expression that matches *relative paths* from the
source path. Glob expressions can be literal string compares. Or the
following special syntax is recognized:

* `?` matches any single character.
* `*` matches any (possibly empty) sequence of characters.
* `**` matches the current directory and arbitrary subdirectories. This sequence
  must form a single path component, so both **a and b** are invalid and will
  result in an error. A sequence of more than two consecutive * characters is
  also invalid.
* `[...]` matches any character inside the brackets. Character sequences can also
  specify ranges of characters, as ordered by Unicode, so e.g. [0-9] specifies any
  character between 0 and 9 inclusive. An unclosed bracket is invalid.
* `[!...]` is the negation of `[...]`, i.e. it matches any characters not in the
  brackets.
* The metacharacters `?`, `*`, `[`, `]` can be matched by using brackets (e.g.
  `[?]`). When a `]` occurs immediately following `[` or `[!` then it is
  interpreted as being part of, rather then ending, the character set, so `]` and
  `NOT ]` can be matched by `[]]` and `[!]]` respectively. The `-` character can
  be specified inside a character sequence pattern by placing it at the start or
  the end, e.g. `[abc-]`.

Currently, --exclude only applies to the relative path of nested bundles within
the main bundle to sign. e.g. if you sign `MyApp.app` and it has a
`Contents/Frameworks/MyFramework.framework` that you wish to exclude, you would
`--exclude Contents/Frameworks/MyFramework.framework` or even
`--exclude Contents/Frameworks/**` to exclude the entire directory tree.

Exclusions will still be copied and parents that need to reference exclude
entities will continue to do so. If you wish to make a file or directory
disappear, create a new directory without the file(s) and sign that.

To exclude all nested bundles from being signed and only sign the main bundle
(the default behavior of ``codesign`` without ``--deep``), use `--exclude '**'`.
";

const APPLE_TIMESTAMP_URL: &str = "http://timestamp.apple.com/ts01";

const SUPPORTED_HASHES: [&str; 6] = [
    "none",
    "sha1",
    "sha256",
    "sha256-truncated",
    "sha384",
    "sha512",
];

const KEYCHAIN_DOMAINS: [&str; 4] = ["user", "system", "common", "dynamic"];

fn parse_scoped_value(s: &str) -> Result<(SettingsScope, &str), AppleCodesignError> {
    let parts = s.splitn(2, ':').collect::<Vec<_>>();

    match parts.len() {
        1 => Ok((SettingsScope::Main, s)),
        2 => Ok((SettingsScope::try_from(parts[0])?, parts[1])),
        _ => Err(AppleCodesignError::CliBadArgument),
    }
}

#[derive(Args, Clone)]
struct CertificateSource {
    /// Smartcard slot number of signing certificate to use (9c is common)
    #[arg(long)]
    smartcard_slot: Option<String>,

    /// Environment variable holding the smartcard PIN
    #[arg(long)]
    smartcard_pin_env: Option<String>,

    /// (macOS only) Keychain domain to operate on
    #[arg(long, group = "keychain", value_parser = KEYCHAIN_DOMAINS)]
    keychain_domain: Vec<String>,

    /// (macOS only) SHA-256 fingerprint of certificate in Keychain to use
    #[arg(long, group = "keychain")]
    keychain_fingerprint: Option<String>,

    /// Path to file containing PEM encoded certificate/key data
    #[arg(long)]
    pem_source: Vec<String>,

    /// Path to file containing DER encoded certificate data
    #[arg(long)]
    der_source: Vec<String>,

    /// Path to a .p12/PFX file containing a certificate key pair
    #[arg(long = "p12-file", alias = "pfx-file")]
    p12_path: Option<String>,

    /// The password to use to open the --p12-file file
    #[arg(long, alias = "pfx-password", group = "p12-password")]
    p12_password: Option<String>,

    // TODO conflicts with p12_password
    /// Path to file containing password for opening --p12-file file
    #[arg(long, alias = "pfx-password-file", group = "p12-password")]
    p12_password_file: Option<String>,

    /// Send signing requests to a remote signer
    #[arg(long)]
    remote_signer: bool,

    /// Base64 encoded public key data describing the signer
    #[arg(long, group = "remote-initialization")]
    remote_public_key: Option<String>,

    /// PEM encoded public key data describing the signer
    #[arg(long, group = "remote-initialization", group = "remote-initialization")]
    remote_public_key_pem_file: Option<String>,

    /// Shared secret used for remote signing
    #[arg(long, group = "remote-initialization")]
    remote_shared_secret: Option<String>,

    /// Environment variable holding the shared secret used for remote signing
    #[arg(long, group = "remote-initialization")]
    remote_shared_secret_env: Option<String>,

    /// URL of a remote code signing server
    #[arg(long, default_value = crate::remote_signing::DEFAULT_SERVER_URL)]
    remote_signing_url: String,
}

impl CertificateSource {
    fn resolve_certificates(
        &self,
        scan_smartcard: bool,
    ) -> Result<(Vec<Box<dyn PrivateKey>>, Vec<CapturedX509Certificate>), AppleCodesignError> {
        let mut keys: Vec<Box<dyn PrivateKey>> = vec![];
        let mut certs = vec![];

        if let Some(p12_path) = &self.p12_path {
            let p12_data = std::fs::read(p12_path)?;

            let p12_password = if let Some(password) = &self.p12_password {
                password.to_string()
            } else if let Some(path) = &self.p12_password_file {
                std::fs::read_to_string(path)?
                    .lines()
                    .next()
                    .expect("should get a single line")
                    .to_string()
            } else {
                dialoguer::Password::new()
                    .with_prompt("Please enter password for p12 file")
                    .interact()?
            };

            let (cert, key) = parse_pfx_data(&p12_data, &p12_password)?;

            keys.push(Box::new(key));
            certs.push(cert);
        }

        for pem_source in &self.pem_source {
            warn!("reading PEM data from {}", pem_source);
            let pem_data = std::fs::read(pem_source)?;

            for pem in pem::parse_many(pem_data).map_err(AppleCodesignError::CertificatePem)? {
                match pem.tag() {
                    "CERTIFICATE" => {
                        certs.push(CapturedX509Certificate::from_der(pem.contents())?);
                    }
                    "PRIVATE KEY" => {
                        keys.push(Box::new(InMemoryPrivateKey::from_pkcs8_der(
                            pem.contents(),
                        )?));
                    }
                    "RSA PRIVATE KEY" => {
                        keys.push(Box::new(InMemoryPrivateKey::from_pkcs1_der(
                            pem.contents(),
                        )?));
                    }
                    tag => warn!("(unhandled PEM tag {}; ignoring)", tag),
                }
            }
        }

        for der_source in &self.der_source {
            warn!("reading DER file {}", der_source);
            let der_data = std::fs::read(der_source)?;

            certs.push(CapturedX509Certificate::from_der(der_data)?);
        }

        self.find_certificates_in_keychain(&mut keys, &mut certs)?;

        if scan_smartcard {
            if let Some(slot) = &self.smartcard_slot {
                handle_smartcard_sign_slot(
                    slot,
                    self.smartcard_pin_env.as_ref().map(|x| x.as_str()),
                    &mut keys,
                    &mut certs,
                )?;
            }
        }

        let remote_signing_url = if self.remote_signer {
            Some(self.remote_signing_url.clone())
        } else {
            None
        };

        if let Some(remote_signing_url) = remote_signing_url {
            let initiator = self.get_remote_signing_initiator()?;

            let client = UnjoinedSigningClient::new_initiator(
                remote_signing_url,
                initiator,
                Some(print_session_join),
            )?;

            // As part of the handshake we obtained the public certificates from the signer.
            // So make them the canonical set.
            if !certs.is_empty() {
                warn!(
                    "ignoring {} local certificates and using remote signer's certificate(s)",
                    certs.len()
                );
            }

            certs = vec![client.signing_certificate().clone()];
            certs.extend(client.certificate_chain().iter().cloned());

            // The client implements Sign, so we just use it as the private key.
            keys = vec![Box::new(client)];
        }

        Ok((keys, certs))
    }

    #[cfg(target_os = "macos")]
    fn find_certificates_in_keychain(
        &self,
        private_keys: &mut Vec<Box<dyn PrivateKey>>,
        public_certificates: &mut Vec<CapturedX509Certificate>,
    ) -> Result<(), AppleCodesignError> {
        // No arguments pertinent to keychains. Don't even speak to the
        // keychain API since this could only error.
        if self.keychain_domain.is_empty() && self.keychain_fingerprint.is_none() {
            return Ok(());
        }

        // Collect all the keychain domains to search.
        let domains = if self.keychain_domain.is_empty() {
            vec!["user".to_string()]
        } else {
            self.keychain_domain.clone()
        };

        let domains = domains
            .into_iter()
            .map(|domain| {
                KeychainDomain::try_from(domain.as_str())
                    .expect("clap should have validated domain values")
            })
            .collect::<Vec<_>>();

        // Now iterate all the keychains and try to find requested certificates.

        for domain in domains {
            for cert in keychain_find_code_signing_certificates(domain, None)? {
                let matches = if let Some(wanted_fingerprint) = &self.keychain_fingerprint {
                    let got_fingerprint = hex::encode(cert.sha256_fingerprint()?.as_ref());

                    wanted_fingerprint.to_ascii_lowercase() == got_fingerprint.to_ascii_lowercase()
                } else {
                    false
                };

                if matches {
                    public_certificates.push(cert.as_captured_x509_certificate());
                    private_keys.push(Box::new(cert));
                }
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn find_certificates_in_keychain(
        &self,
        _private_keys: &mut [Box<dyn PrivateKey>],
        _public_certificates: &mut [CapturedX509Certificate],
    ) -> Result<(), AppleCodesignError> {
        if !self.keychain_domain.is_empty() || self.keychain_fingerprint.is_some() {
            error!(
                "--keychain* arguments only supported on macOS and will be ignored on this platform"
            );
        }

        Ok(())
    }

    fn get_remote_signing_initiator(
        &self,
    ) -> Result<Box<dyn SessionInitiatePeer>, RemoteSignError> {
        let server_url = self.remote_signing_url.clone();

        if let Some(public_key_data) = &self.remote_public_key {
            let public_key_data = STANDARD_ENGINE.decode(public_key_data)?;

            Ok(Box::new(PublicKeyInitiator::new(
                public_key_data,
                Some(server_url),
            )?))
        } else if let Some(path) = &self.remote_public_key_pem_file {
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

            Ok(Box::new(PublicKeyInitiator::new(
                spki_der,
                Some(server_url),
            )?))
        } else if let Some(env) = &self.remote_shared_secret_env {
            let secret = std::env::var(env).map_err(|_| {
                RemoteSignError::ClientState(
                    "failed reading from shared secret environment variable",
                )
            })?;

            Ok(Box::new(SharedSecretInitiator::new(
                secret.as_bytes().to_vec(),
            )?))
        } else if let Some(value) = &self.remote_shared_secret {
            Ok(Box::new(SharedSecretInitiator::new(
                value.as_bytes().to_vec(),
            )?))
        } else {
            error!("no arguments provided to establish session with remote signer");
            error!(
            "specify --remote-public-key, --remote-shared-secret-env, or --remote-shared-secret"
        );
            Err(RemoteSignError::ClientState(
                "unable to initiate remote signing",
            ))
        }
    }
}

#[cfg(feature = "notarize")]
#[derive(Args)]
struct NotaryApi {
    /// Path to a JSON file containing the API Key
    #[arg(long, group = "source")]
    api_key_path: Option<PathBuf>,

    /// App Store Connect Issuer ID (likely a UUID)
    #[arg(long, requires = "api_key")]
    api_issuer: Option<String>,

    #[arg(long, requires = "api_issuer")]
    /// App Store Connect API Key ID
    api_key: Option<String>,
}

#[cfg(feature = "notarize")]
impl NotaryApi {
    /// Resolve a notarizer from arguments.
    fn notarizer(&self) -> Result<Notarizer, AppleCodesignError> {
        if let Some(api_key_path) = &self.api_key_path {
            Notarizer::from_api_key(api_key_path)
        } else if let (Some(issuer), Some(key)) = (&self.api_issuer, &self.api_key) {
            Notarizer::from_api_key_id(issuer, key)
        } else {
            Err(AppleCodesignError::NotarizeNoAuthCredentials)
        }
    }
}

#[derive(Args)]
struct YubikeyPolicy {
    /// Smartcard touch policy to protect key access
    #[arg(long, value_parser = ["default", "always", "never", "cached"], default_value = "default")]
    touch_policy: String,

    /// Smartcard pin prompt policy to protect key access
    #[arg(long, value_parser = ["default", "never", "once", "always"], default_value = "default")]
    pin_policy: String,
}

#[cfg(feature = "yubikey")]
fn str_to_touch_policy(s: &str) -> Result<TouchPolicy, AppleCodesignError> {
    match s {
        "default" => Ok(TouchPolicy::Default),
        "never" => Ok(TouchPolicy::Never),
        "always" => Ok(TouchPolicy::Always),
        "cached" => Ok(TouchPolicy::Cached),
        _ => Err(AppleCodesignError::CliBadArgument),
    }
}

#[cfg(feature = "yubikey")]
fn str_to_pin_policy(s: &str) -> Result<PinPolicy, AppleCodesignError> {
    match s {
        "default" => Ok(PinPolicy::Default),
        "never" => Ok(PinPolicy::Never),
        "once" => Ok(PinPolicy::Once),
        "always" => Ok(PinPolicy::Always),
        _ => Err(AppleCodesignError::CliBadArgument),
    }
}

fn print_certificate_info(cert: &CapturedX509Certificate) -> Result<(), AppleCodesignError> {
    println!(
        "Subject CN:                  {}",
        cert.subject_common_name()
            .unwrap_or_else(|| "<missing>".to_string())
    );
    println!(
        "Issuer CN:                   {}",
        cert.issuer_common_name()
            .unwrap_or_else(|| "<missing>".to_string())
    );
    println!("Subject is Issuer?:          {}", cert.subject_is_issuer());
    println!(
        "Team ID:                     {}",
        cert.apple_team_id()
            .unwrap_or_else(|| "<missing>".to_string())
    );
    println!(
        "SHA-1 fingerprint:           {}",
        hex::encode(cert.sha1_fingerprint()?)
    );
    println!(
        "SHA-256 fingerprint:         {}",
        hex::encode(cert.sha256_fingerprint()?)
    );
    if let Some(alg) = cert.key_algorithm() {
        println!("Key Algorithm:               {alg}");
    }
    if let Some(alg) = cert.signature_algorithm() {
        println!("Signature Algorithm:         {alg}");
    }
    println!(
        "Public Key Data:             {}",
        STANDARD_ENGINE.encode(
            cert.to_public_key_der()
                .map_err(|e| AppleCodesignError::X509Parse(format!(
                    "error constructing SPKI: {e}"
                )))?
        )
    );
    println!(
        "Signed by Apple?:            {}",
        cert.chains_to_apple_root_ca()
    );
    if cert.chains_to_apple_root_ca() {
        println!("Apple Issuing Chain:");
        for signer in cert.apple_issuing_chain() {
            println!(
                "  - {}",
                signer
                    .subject_common_name()
                    .unwrap_or_else(|| "<unknown>".to_string())
            );
        }
    }

    println!(
        "Guessed Certificate Profile: {}",
        if let Some(profile) = cert.apple_guess_profile() {
            format!("{profile:?}")
        } else {
            "none".to_string()
        }
    );
    println!("Is Apple Root CA?:           {}", cert.is_apple_root_ca());
    println!(
        "Is Apple Intermediate CA?:   {}",
        cert.is_apple_intermediate_ca()
    );
    println!(
        "Apple CA Extension:          {}",
        if let Some(ext) = cert.apple_ca_extension() {
            format!("{} ({:?})", ext.as_oid(), ext)
        } else {
            "none".to_string()
        }
    );
    println!("Apple Extended Key Usage Purpose Extensions:");
    for purpose in cert.apple_extended_key_usage_purposes() {
        println!("  - {} ({:?})", purpose.as_oid(), purpose);
    }
    println!("Apple Code Signing Extensions:");
    for ext in cert.apple_code_signing_extensions() {
        println!("  - {} ({:?})", ext.as_oid(), ext);
    }
    print!(
        "\n{}",
        cert.to_public_key_pem(Default::default())
            .map_err(|e| AppleCodesignError::X509Parse(format!("error constructing SPKI: {e}")))?
    );
    print!("\n{}", cert.encode_pem());

    Ok(())
}

fn print_session_join(sjs_base64: &str, sjs_pem: &str) -> Result<(), RemoteSignError> {
    error!("");
    error!("Run the following command to join this signing session:");
    error!("");
    error!("    rcodesign remote-sign {}", sjs_base64);
    error!("");
    error!("Or if this output is too long, paste the following output:");
    error!("");
    for line in sjs_pem.lines() {
        error!("{}", line);
    }
    error!("");
    error!("Into an interactive editor using:");
    error!("");
    error!("    rcodesign remote-sign --editor");
    error!("");
    error!("Or into a new file whose path you define with:");
    error!("");
    error!("    rcodesign remote-sign --sjs-path /path/to/file/you/just/saved");
    error!("");
    error!("(waiting for remote signer to join)");

    Ok(())
}

#[allow(unused)]
fn prompt_smartcard_pin() -> Result<Vec<u8>, AppleCodesignError> {
    let pin = dialoguer::Password::new()
        .with_prompt("Please enter device PIN")
        .interact()?;

    Ok(pin.as_bytes().to_vec())
}

#[cfg(feature = "yubikey")]
fn handle_smartcard_sign_slot(
    slot: &str,
    pin_env_var: Option<&str>,
    private_keys: &mut Vec<Box<dyn PrivateKey>>,
    public_certificates: &mut Vec<CapturedX509Certificate>,
) -> Result<(), AppleCodesignError> {
    let slot_id = ::yubikey::piv::SlotId::from_str(slot)?;
    let formatted = hex::encode([u8::from(slot_id)]);
    let mut yk = YubiKey::new()?;

    if let Some(pin_var) = pin_env_var {
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

    if let Some(cert) = yk.get_certificate_signer(slot_id)? {
        warn!("using certificate in smartcard slot {}", formatted);
        public_certificates.push(cert.certificate().clone());
        private_keys.push(Box::new(cert));

        Ok(())
    } else {
        Err(AppleCodesignError::SmartcardNoCertificate(formatted))
    }
}

#[cfg(not(feature = "yubikey"))]
fn handle_smartcard_sign_slot(
    _slot: &str,
    _pin_env_var: Option<&str>,
    _private_keys: &mut [Box<dyn PrivateKey>],
    _public_certificates: &mut [CapturedX509Certificate],
) -> Result<(), AppleCodesignError> {
    error!("smartcard support not available; ignoring --smartcard-slot");

    Ok(())
}

#[derive(Parser)]
struct AnalyzeCertificate {
    #[command(flatten)]
    certificate: CertificateSource,
}

fn command_analyze_certificate(args: &AnalyzeCertificate) -> Result<(), AppleCodesignError> {
    let certs = args.certificate.resolve_certificates(true)?.1;

    for (i, cert) in certs.into_iter().enumerate() {
        println!("# Certificate {i}");
        println!();
        print_certificate_info(&cert)?;
        println!();
    }

    Ok(())
}

#[derive(Parser)]
struct ComputeCodeHashes {
    /// Path to Mach-O binary to examine.
    path: PathBuf,

    /// Hashing algorithm to use.
    #[arg(long, default_value_t = DigestType::Sha256)]
    hash: DigestType,

    /// Chunk size to digest over.
    #[arg(long, default_value = "4096")]
    page_size: usize,

    /// Index of Mach-O binary to operate on within a universal/fat binary
    #[arg(long, default_value = "0")]
    universal_index: usize,
}

fn command_compute_code_hashes(args: &ComputeCodeHashes) -> Result<(), AppleCodesignError> {
    let data = std::fs::read(&args.path)?;
    let mach = MachFile::parse(&data)?;
    let macho = mach.nth_macho(args.universal_index)?;

    let hashes = macho.code_digests(args.hash, args.page_size)?;

    for hash in hashes {
        println!("{}", hex::encode(hash));
    }

    Ok(())
}

#[derive(Parser)]
struct DiffSignatures {
    /// The first path to compare
    path0: PathBuf,

    /// The second path to compare
    path1: PathBuf,
}

fn command_diff_signatures(args: &DiffSignatures) -> Result<(), AppleCodesignError> {
    let reader = SignatureReader::from_path(&args.path0)?;

    let a_entities = reader.entities()?;

    let reader = SignatureReader::from_path(&args.path1)?;
    let b_entities = reader.entities()?;

    let a = serde_yaml::to_string(&a_entities)?;
    let b = serde_yaml::to_string(&b_entities)?;

    let Changeset { diffs, .. } = Changeset::new(&a, &b, "\n");

    for item in diffs {
        match item {
            Difference::Same(ref x) => {
                for line in x.lines() {
                    println!(" {line}");
                }
            }
            Difference::Add(ref x) => {
                for line in x.lines() {
                    println!("+{line}");
                }
            }
            Difference::Rem(ref x) => {
                for line in x.lines() {
                    println!("-{line}");
                }
            }
        }
    }

    Ok(())
}

#[cfg(feature = "notarize")]
const ENCODE_APP_STORE_CONNECT_API_KEY_ABOUT: &str = "\
Encode an App Store Connect API Key to JSON.

App Store Connect API Keys
(https://developer.apple.com/documentation/appstoreconnectapi/creating_api_keys_for_app_store_connect_api)
are defined by 3 components:

* The Issuer ID (likely a UUID)
* A Key ID (an alphanumeric value like `DEADBEEF42`)
* A PEM encoded ECDSA private key (typically a file beginning with
  `-----BEGIN PRIVATE KEY-----`).

This command is used to encode all API Key components into a single JSON
object so you only have to refer to a single entity when performing
operations (like notarization) using these API Keys.

The API Key components are specified as positional arguments.

By default, the JSON encoded unified representation is printed to stdout.
You can write to a file instead by passing `--output-path <path>`.

# Security Considerations

The App Store Connect API Key contains a private key and its value should be
treated as sensitive: if an unwanted party obtains your private key, they
effectively have access to your App Store Connect account.

When this command writes JSON files, an attempt is made to limit access
to the file. However, file access restrictions may not be as secure as you
want. Security conscious individuals should audit the permissions of the
file and adjust accordingly.
";

#[cfg(feature = "notarize")]
#[derive(Parser)]
struct EncodeAppStoreConnectApiKey {
    /// Path to a JSON file to create the output to
    #[arg(short = 'o', long)]
    output_path: Option<PathBuf>,

    /// The issuer of the API Token. Likely a UUID
    issuer_id: String,

    /// The Key ID. A short alphanumeric string like DEADBEEF42
    key_id: String,

    /// Path to a file containing the private key downloaded from Apple
    private_key_path: PathBuf,
}

#[cfg(feature = "notarize")]
fn command_encode_app_store_connect_api_key(
    args: &EncodeAppStoreConnectApiKey,
) -> Result<(), AppleCodesignError> {
    let unified = app_store_connect::UnifiedApiKey::from_ecdsa_pem_path(
        &args.issuer_id,
        &args.key_id,
        &args.private_key_path,
    )?;

    if let Some(output_path) = &args.output_path {
        eprintln!("writing unified key JSON to {}", output_path.display());
        unified.write_json_file(output_path)?;
        eprintln!(
            "consider auditing the file's access permissions to ensure its content remains secure"
        );
    } else {
        println!("{}", unified.to_json_string()?);
    }

    Ok(())
}

fn print_signed_data(
    prefix: &str,
    signed_data: &SignedData,
    external_content: Option<Vec<u8>>,
) -> Result<(), AppleCodesignError> {
    println!(
        "{}signed content (embedded): {:?}",
        prefix,
        signed_data.signed_content().map(hex::encode)
    );
    println!(
        "{}signed content (external): {:?}... ({} bytes)",
        prefix,
        external_content.as_ref().map(|x| hex::encode(&x[0..40])),
        external_content.as_ref().map(|x| x.len()).unwrap_or(0),
    );

    let content = if let Some(v) = signed_data.signed_content() {
        Some(v)
    } else {
        external_content.as_ref().map(|v| v.as_ref())
    };

    if let Some(content) = content {
        println!(
            "{}signed content SHA-1:   {}",
            prefix,
            hex::encode(DigestType::Sha1.digest_data(content)?)
        );
        println!(
            "{}signed content SHA-256: {}",
            prefix,
            hex::encode(DigestType::Sha256.digest_data(content)?)
        );
        println!(
            "{}signed content SHA-384: {}",
            prefix,
            hex::encode(DigestType::Sha384.digest_data(content)?)
        );
        println!(
            "{}signed content SHA-512: {}",
            prefix,
            hex::encode(DigestType::Sha512.digest_data(content)?)
        );
    }
    println!(
        "{}certificate count: {}",
        prefix,
        signed_data.certificates().count()
    );
    for (i, cert) in signed_data.certificates().enumerate() {
        println!(
            "{}certificate #{}: subject CN={}; self signed={}",
            prefix,
            i,
            cert.subject_common_name()
                .unwrap_or_else(|| "<unknown>".to_string()),
            cert.subject_is_issuer()
        );
    }
    println!("{}signer count: {}", prefix, signed_data.signers().count());
    for (i, signer) in signed_data.signers().enumerate() {
        println!(
            "{}signer #{}: digest algorithm: {:?}",
            prefix,
            i,
            signer.digest_algorithm()
        );
        println!(
            "{}signer #{}: signature algorithm: {:?}",
            prefix,
            i,
            signer.signature_algorithm()
        );

        if let Some(sa) = signer.signed_attributes() {
            println!(
                "{}signer #{}: content type: {}",
                prefix,
                i,
                sa.content_type()
            );
            println!(
                "{}signer #{}: message digest: {}",
                prefix,
                i,
                hex::encode(sa.message_digest())
            );
            println!(
                "{}signer #{}: signing time: {:?}",
                prefix,
                i,
                sa.signing_time()
            );
        }

        let digested_data = signer.signed_content_with_signed_data(signed_data);

        println!(
            "{}signer #{}: signature content SHA-1:   {}",
            prefix,
            i,
            hex::encode(DigestType::Sha1.digest_data(&digested_data)?)
        );
        println!(
            "{}signer #{}: signature content SHA-256: {}",
            prefix,
            i,
            hex::encode(DigestType::Sha256.digest_data(&digested_data)?)
        );
        println!(
            "{}signer #{}: signature content SHA-384: {}",
            prefix,
            i,
            hex::encode(DigestType::Sha384.digest_data(&digested_data)?)
        );
        println!(
            "{}signer #{}: signature content SHA-512: {}",
            prefix,
            i,
            hex::encode(DigestType::Sha512.digest_data(&digested_data)?)
        );

        if signed_data.signed_content().is_some() {
            println!(
                "{}signer #{}: digest valid: {}",
                prefix,
                i,
                signer
                    .verify_message_digest_with_signed_data(signed_data)
                    .is_ok()
            );
        }
        println!(
            "{}signer #{}: signature valid: {}",
            prefix,
            i,
            signer
                .verify_signature_with_signed_data(signed_data)
                .is_ok()
        );

        println!(
            "{}signer #{}: time-stamp token present: {}",
            prefix,
            i,
            signer.time_stamp_token_signed_data()?.is_some()
        );

        if let Some(tsp_signed_data) = signer.time_stamp_token_signed_data()? {
            let prefix = format!("{prefix}signer #{i}: time-stamp token: ");

            print_signed_data(&prefix, &tsp_signed_data, None)?;
        }
    }

    Ok(())
}

const EXTRACT_DATA: [&str; 21] = [
    "blobs",
    "cms-info",
    "cms-pem",
    "cms-raw",
    "cms",
    "code-directory-raw",
    "code-directory-serialized-raw",
    "code-directory-serialized",
    "code-directory",
    "linkedit-info",
    "linkedit-segment-raw",
    "macho-load-commands",
    "macho-segments",
    "macho-target",
    "requirements-raw",
    "requirements-rust",
    "requirements-serialized-raw",
    "requirements-serialized",
    "requirements",
    "signature-raw",
    "superblob",
];

#[derive(Parser)]
struct Extract {
    /// Path to Mach-O binary to examine
    path: PathBuf,

    /// Which data to extract and how to format it
    #[arg(long, value_parser = EXTRACT_DATA, default_value = "linkedit-info")]
    data: String,

    /// Index of Mach-O binary to operate on within a universal/fat binary
    #[arg(long, default_value = "0")]
    universal_index: usize,
}

fn command_extract(args: &Extract) -> Result<(), AppleCodesignError> {
    let data = std::fs::read(&args.path)?;
    let mach = MachFile::parse(&data)?;
    let macho = mach.nth_macho(args.universal_index)?;

    match args.data.as_str() {
        "blobs" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            for blob in embedded.blobs {
                let parsed = blob.into_parsed_blob()?;
                println!("{parsed:#?}");
            }
        }
        "cms-info" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(cms) = embedded.signature_data()? {
                let signed_data = SignedData::parse_ber(cms)?;

                let cd_data = if let Ok(Some(blob)) = embedded.code_directory() {
                    Some(blob.to_blob_bytes()?)
                } else {
                    None
                };

                print_signed_data("", &signed_data, cd_data)?;
            } else {
                eprintln!("no CMS data");
            }
        }
        "cms-pem" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(cms) = embedded.signature_data()? {
                print!("{}", pem::encode(&pem::Pem::new("PKCS7", cms.to_vec())));
            } else {
                eprintln!("no CMS data");
            }
        }
        "cms-raw" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(cms) = embedded.signature_data()? {
                std::io::stdout().write_all(cms)?;
            } else {
                eprintln!("no CMS data");
            }
        }
        "cms" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(signed_data) = embedded.signed_data()? {
                println!("{signed_data:#?}");
            } else {
                eprintln!("no CMS data");
            }
        }
        "code-directory-raw" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(blob) = embedded.find_slot(CodeSigningSlot::CodeDirectory) {
                std::io::stdout().write_all(blob.data)?;
            } else {
                eprintln!("no code directory");
            }
        }
        "code-directory-serialized-raw" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Ok(Some(cd)) = embedded.code_directory() {
                std::io::stdout().write_all(&cd.to_blob_bytes()?)?;
            } else {
                eprintln!("no code directory");
            }
        }
        "code-directory-serialized" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Ok(Some(cd)) = embedded.code_directory() {
                let serialized = cd.to_blob_bytes()?;
                println!("{:#?}", CodeDirectoryBlob::from_blob_bytes(&serialized)?);
            }
        }
        "code-directory" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(cd) = embedded.code_directory()? {
                println!("{cd:#?}");
            } else {
                eprintln!("no code directory");
            }
        }
        "linkedit-info" => {
            let sig = macho
                .find_signature_data()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;
            println!("__LINKEDIT segment index: {}", sig.linkedit_segment_index);
            println!(
                "__LINKEDIT segment start offset: {}",
                sig.linkedit_segment_start_offset
            );
            println!(
                "__LINKEDIT segment end offset: {}",
                sig.linkedit_segment_end_offset
            );
            println!(
                "__LINKEDIT segment size: {}",
                sig.linkedit_segment_data.len()
            );
            println!(
                "__LINKEDIT signature global start offset: {}",
                sig.linkedit_signature_start_offset
            );
            println!(
                "__LINKEDIT signature global end offset: {}",
                sig.linkedit_signature_end_offset
            );
            println!(
                "__LINKEDIT signature local segment start offset: {}",
                sig.signature_start_offset
            );
            println!(
                "__LINKEDIT signature local segment end offset: {}",
                sig.signature_end_offset
            );
            println!("__LINKEDIT signature size: {}", sig.signature_data.len());
        }
        "linkedit-segment-raw" => {
            let sig = macho
                .find_signature_data()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;
            std::io::stdout().write_all(sig.linkedit_segment_data)?;
        }
        "macho-load-commands" => {
            println!("load command count: {}", macho.macho.load_commands.len());

            for command in &macho.macho.load_commands {
                println!(
                    "{}; offsets=0x{:x}-0x{:x} ({}-{}); size={}",
                    goblin::mach::load_command::cmd_to_str(command.command.cmd()),
                    command.offset,
                    command.offset + command.command.cmdsize(),
                    command.offset,
                    command.offset + command.command.cmdsize(),
                    command.command.cmdsize(),
                );
            }
        }
        "macho-segments" => {
            println!("segments count: {}", macho.macho.segments.len());
            for (segment_index, segment) in macho.macho.segments.iter().enumerate() {
                let sections = segment.sections()?;

                println!(
                    "segment #{}; {}; offsets=0x{:x}-0x{:x}; vm/file size {}/{}; section count {}",
                    segment_index,
                    segment.name()?,
                    segment.fileoff,
                    segment.fileoff as usize + segment.data.len(),
                    segment.vmsize,
                    segment.filesize,
                    sections.len()
                );
                for (section_index, (section, _)) in sections.into_iter().enumerate() {
                    println!(
                        "segment #{}; section #{}: {}; segment offsets=0x{:x}-0x{:x} size {}",
                        segment_index,
                        section_index,
                        section.name()?,
                        section.offset,
                        section.offset as u64 + section.size,
                        section.size
                    );
                }
            }
        }
        "macho-target" => {
            if let Some(target) = macho.find_targeting()? {
                println!("Platform: {}", target.platform);
                println!("Minimum OS: {}", target.minimum_os_version);
                println!("SDK: {}", target.sdk_version);
            } else {
                println!("Unable to resolve Mach-O targeting from load commands");
            }
        }
        "requirements-raw" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(blob) = embedded.find_slot(CodeSigningSlot::RequirementSet) {
                std::io::stdout().write_all(blob.data)?;
            } else {
                eprintln!("no requirements");
            }
        }
        "requirements-rust" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(reqs) = embedded.code_requirements()? {
                for (typ, req) in &reqs.requirements {
                    for expr in req.parse_expressions()?.iter() {
                        println!("{typ} => {expr:#?}");
                    }
                }
            } else {
                eprintln!("no requirements");
            }
        }
        "requirements-serialized-raw" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(reqs) = embedded.code_requirements()? {
                std::io::stdout().write_all(&reqs.to_blob_bytes()?)?;
            } else {
                eprintln!("no requirements");
            }
        }
        "requirements-serialized" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(reqs) = embedded.code_requirements()? {
                let serialized = reqs.to_blob_bytes()?;
                println!("{:#?}", RequirementSetBlob::from_blob_bytes(&serialized)?);
            } else {
                eprintln!("no requirements");
            }
        }
        "requirements" => {
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            if let Some(reqs) = embedded.code_requirements()? {
                for (typ, req) in &reqs.requirements {
                    for expr in req.parse_expressions()?.iter() {
                        println!("{typ} => {expr}");
                    }
                }
            } else {
                eprintln!("no requirements");
            }
        }
        "signature-raw" => {
            let sig = macho
                .find_signature_data()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;
            std::io::stdout().write_all(sig.signature_data)?;
        }
        "superblob" => {
            let sig = macho
                .find_signature_data()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;
            let embedded = macho
                .code_signature()?
                .ok_or(AppleCodesignError::BinaryNoCodeSignature)?;

            println!("file start offset: {}", sig.linkedit_signature_start_offset);
            println!("file end offset: {}", sig.linkedit_signature_end_offset);
            println!("__LINKEDIT start offset: {}", sig.signature_start_offset);
            println!("__LINKEDIT end offset: {}", sig.signature_end_offset);
            println!("length: {}", embedded.length);
            println!("blob count: {}", embedded.count);
            println!("blobs:");
            for blob in embedded.blobs {
                println!("- index: {}", blob.index);
                println!(
                    "  offsets: 0x{:x}-0x{:x} ({}-{})",
                    blob.offset,
                    blob.offset + blob.length - 1,
                    blob.offset,
                    blob.offset + blob.length - 1
                );
                println!("  length: {}", blob.length);
                println!("  slot: {:?}", blob.slot);
                println!("  magic: {:?} (0x{:x})", blob.magic, u32::from(blob.magic));
                println!(
                    "  sha1: {}",
                    hex::encode(blob.digest_with(DigestType::Sha1)?)
                );
                println!(
                    "  sha256: {}",
                    hex::encode(blob.digest_with(DigestType::Sha256)?)
                );
                println!(
                    "  sha256-truncated: {}",
                    hex::encode(blob.digest_with(DigestType::Sha256Truncated)?)
                );
                println!(
                    "  sha384: {}",
                    hex::encode(blob.digest_with(DigestType::Sha384)?),
                );
                println!(
                    "  sha512: {}",
                    hex::encode(blob.digest_with(DigestType::Sha512)?),
                );
                println!(
                    "  sha1-base64: {}",
                    STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha1)?)
                );
                println!(
                    "  sha256-base64: {}",
                    STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha256)?)
                );
                println!(
                    "  sha256-truncated-base64: {}",
                    STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha256Truncated)?)
                );
                println!(
                    "  sha384-base64: {}",
                    STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha384)?)
                );
                println!(
                    "  sha512-base64: {}",
                    STANDARD_ENGINE.encode(blob.digest_with(DigestType::Sha512)?)
                );
            }
        }
        x => panic!("unhandled format: {x}"),
    }

    Ok(())
}

#[derive(Parser)]
struct GenerateCertificateSigningRequest {
    /// Path to file to write PEM encoded CSR to
    #[arg(long)]
    csr_pem_path: Option<PathBuf>,

    #[command(flatten)]
    certificate: CertificateSource,
}

fn command_generate_certificate_signing_request(
    args: &GenerateCertificateSigningRequest,
) -> Result<(), AppleCodesignError> {
    let private_keys = args.certificate.resolve_certificates(true)?.0;

    let private_key = if private_keys.is_empty() {
        error!("no private keys found; a private key is required to sign a certificate signing request");
        return Err(AppleCodesignError::CliBadArgument);
    } else if private_keys.len() > 1 {
        error!(
            "at most 1 private key can be present (found {}); aborting",
            private_keys.len()
        );
        return Err(AppleCodesignError::CliBadArgument);
    } else {
        private_keys.into_iter().next().expect("checked size above")
    };

    let key_algorithm = private_key.key_algorithm().ok_or_else(|| {
        error!("unable to determine key algorithm of private key (please report this issue)");
        AppleCodesignError::CliBadArgument
    })?;

    let mut builder = X509CertificateBuilder::new(key_algorithm);
    builder
        .subject()
        .append_common_name_utf8_string("Apple Code Signing CSR")
        .map_err(|e| AppleCodesignError::CertificateBuildError(format!("{e:?}")))?;

    warn!("generating CSR; you may be prompted to enter credentials to unlock the signing key");
    let pem = builder
        .create_certificate_signing_request(private_key.as_key_info_signer())?
        .encode_pem()?;

    if let Some(dest_path) = &args.csr_pem_path {
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        warn!("writing PEM encoded CSR to {}", dest_path.display());
        std::fs::write(&dest_path, pem.as_bytes())?;
    }

    print!("{pem}");

    Ok(())
}

#[derive(Parser)]
struct GenerateSelfSignedCertificate {
    /// Which key type to use
    #[arg(long, value_parser = ["ecdsa", "ed25519"], default_value = "ecdsa")]
    algorithm: String,

    #[arg(long, value_parser = CertificateProfile::str_names(), default_value = "apple-development")]
    profile: String,

    /// Team ID (this is a short string attached to your Apple Developer account)
    #[arg(long, default_value = "unset")]
    team_id: String,

    /// The name of the person this certificate is for
    #[arg(long)]
    person_name: String,

    /// Country Name (C) value for certificate identifier
    #[arg(long, default_value = "XX")]
    country_name: String,

    /// How many days the certificate should be valid for
    #[arg(long, default_value = "365")]
    validity_days: i64,

    /// Base name of files to write PEM encoded certificate to
    #[arg(long)]
    pem_filename: Option<String>,
}

fn command_generate_self_signed_certificate(
    args: &GenerateSelfSignedCertificate,
) -> Result<(), AppleCodesignError> {
    let algorithm = match args.algorithm.as_str() {
        "ecdsa" => KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1),
        "ed25519" => KeyAlgorithm::Ed25519,
        value => panic!("algorithm values should have been validated by arg parser: {value}"),
    };

    let profile = CertificateProfile::from_str(args.profile.as_str())?;

    let validity_duration = chrono::Duration::days(args.validity_days);

    let (cert, _, raw) = create_self_signed_code_signing_certificate(
        algorithm,
        profile,
        &args.team_id,
        &args.person_name,
        &args.country_name,
        validity_duration,
    )?;

    let cert_pem = cert.encode_pem();
    let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", raw.as_ref().to_vec()));

    let mut wrote_file = false;

    if let Some(pem_filename) = &args.pem_filename {
        let cert_path = PathBuf::from(format!("{pem_filename}.crt"));
        let key_path = PathBuf::from(format!("{pem_filename}.key"));

        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        println!("writing public certificate to {}", cert_path.display());
        std::fs::write(&cert_path, cert_pem.as_bytes())?;
        println!("writing private signing key to {}", key_path.display());
        std::fs::write(&key_path, key_pem.as_bytes())?;

        wrote_file = true;
    }

    if !wrote_file {
        print!("{cert_pem}");
        print!("{key_pem}");
    }

    Ok(())
}

#[derive(Parser)]
struct KeychainExportCertificateChain {
    /// Keychain domain to operate on
    #[arg(long, value_parser = KEYCHAIN_DOMAINS, default_value = "user")]
    domain: String,

    /// Password to unlock the Keychain
    #[arg(long, group = "unlock-password")]
    password: Option<String>,

    /// File containing password to use to unlock the Keychain
    #[arg(long, group = "unlock-password")]
    password_file: Option<PathBuf>,

    /// Print only the issuing certificate chain, not the subject certificate
    #[arg(long)]
    no_print_self: bool,

    /// User ID value of code signing certificate to find and whose CA chain to export
    #[arg(long)]
    user_id: String,
}

#[cfg(target_os = "macos")]
fn command_keychain_export_certificate_chain(
    args: &KeychainExportCertificateChain,
) -> Result<(), AppleCodesignError> {
    let domain = KeychainDomain::try_from(args.domain.as_str())
        .expect("clap should have validated domain values");

    let password = if let Some(path) = &args.password_file {
        let data = std::fs::read_to_string(path)?;

        Some(
            data.lines()
                .next()
                .expect("should get a single line")
                .to_string(),
        )
    } else if let Some(password) = &args.password {
        Some(password.to_string())
    } else {
        None
    };

    let certs = macos_keychain_find_certificate_chain(domain, password.as_deref(), &args.user_id)?;

    for (i, cert) in certs.iter().enumerate() {
        if args.no_print_self && i == 0 {
            continue;
        }

        print!("{}", cert.encode_pem());
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn command_keychain_export_certificate_chain(
    _args: &KeychainExportCertificateChain,
) -> Result<(), AppleCodesignError> {
    Err(AppleCodesignError::CliGeneralError(
        "macOS Keychain export only supported on macOS".to_string(),
    ))
}

#[derive(Parser)]
struct KeychainPrintCertificates {
    /// Keychain domain to operate on
    #[arg(long, value_parser = KEYCHAIN_DOMAINS, default_value = "user")]
    domain: String,
}

#[cfg(target_os = "macos")]
fn command_keychain_print_certificates(
    args: &KeychainPrintCertificates,
) -> Result<(), AppleCodesignError> {
    let domain = KeychainDomain::try_from(args.domain.as_str())
        .expect("clap should have validated domain values");

    let certs = keychain_find_code_signing_certificates(domain, None)?;

    for (i, cert) in certs.into_iter().enumerate() {
        println!("# Certificate {}", i);
        println!();
        print_certificate_info(&cert)?;
        println!();
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn command_keychain_print_certificates(
    _args: &KeychainPrintCertificates,
) -> Result<(), AppleCodesignError> {
    Err(AppleCodesignError::CliGeneralError(
        "macOS Keychain integration supported on macOS".to_string(),
    ))
}

#[cfg(feature = "notarize")]
const NOTARIZE_ABOUT: &str = "\
Submit a notarization request to Apple.

This command is used to submit an asset to Apple for notarization. Given
a path to an asset with a code signature, this command will connect to Apple's
Notary API and upload the asset. It will then optionally wait on the submission
to finish processing (which typically takes a few dozen seconds). If the
asset validates Apple's requirements, Apple will issue a *notarization ticket*
as proof that they approved of it. This ticket is then added to the asset in a
process called *stapling*, which this command can do automatically if the
`--staple` argument is passed.

# App Store Connect API Key

In order to communicate with Apple's servers, you need an App Store Connect
API Key. This requires an Apple Developer account. You can generate an
API Key at https://appstoreconnect.apple.com/access/api.

The recommended mechanism to define the API Key is via `--api-key-path`,
which takes the path to a file containing JSON produced by the
`encode-app-store-connect-api-key` command. See that command's help for
more details.

If you don't wish to use `--api-key-path`, you can define the key components
via the `--api-issuer` and `--api-key` arguments. You will need a file named
`AuthKey_<ID>.p8` in one of the following locations: `$(pwd)/private_keys/`,
`~/private_keys/`, '~/.private_keys/`, and `~/.appstoreconnect/private_keys/`
(searched in that order). The name of the file is derived from the value of
`--api-key`.

In all cases, App Store Connect API Keys can be managed at
https://appstoreconnect.apple.com/access/api.

# Modes of Operation

By default, the `notarize` command will initiate an upload to Apple and exit
once the upload is complete.

Once an upload is performed, Apple will asynchronously process the uploaded
content. This can take seconds to minutes.

To poll Apple's servers and wait on the server-side processing to finish,
specify `--wait`. This will query the state of the processing every few seconds
until it is finished, the max wait time is reached, or an error occurs.

To automatically staple an asset after server-side processing has finished,
specify `--staple`. This implies `--wait`.
";

#[cfg(feature = "notarize")]
#[derive(Parser)]
struct NotaryLog {
    /// The ID of the previous submission to wait on
    submission_id: String,

    #[command(flatten)]
    api: NotaryApi,
}

#[cfg(feature = "notarize")]
fn command_notary_log(args: &NotaryLog) -> Result<(), AppleCodesignError> {
    let notarizer = args.api.notarizer()?;

    let log = notarizer.fetch_notarization_log(&args.submission_id)?;

    for line in serde_json::to_string_pretty(&log)?.lines() {
        println!("{line}");
    }

    Ok(())
}

#[cfg(feature = "notarize")]
#[derive(Parser)]
struct NotarySubmit {
    /// Whether to wait for upload processing to complete
    #[arg(long)]
    wait: bool,

    /// Maximum time in seconds to wait for the upload result
    #[arg(long, default_value = "600")]
    max_wait_seconds: u64,

    /// Staple the notarization ticket after successful upload (implies --wait)
    #[arg(long)]
    staple: bool,

    /// Path to asset to upload
    path: PathBuf,

    #[command(flatten)]
    api: NotaryApi,
}

#[cfg(feature = "notarize")]
fn command_notary_submit(args: &NotarySubmit) -> Result<(), AppleCodesignError> {
    let wait = args.wait || args.staple;

    let wait_limit = if wait {
        Some(std::time::Duration::from_secs(args.max_wait_seconds))
    } else {
        None
    };
    let notarizer = args.api.notarizer()?;

    let upload = notarizer.notarize_path(&args.path, wait_limit)?;

    if args.staple {
        match upload {
            crate::notarization::NotarizationUpload::UploadId(_) => {
                panic!(
                    "NotarizationUpload::UploadId should not be returned if we waited successfully"
                );
            }
            crate::notarization::NotarizationUpload::NotaryResponse(_) => {
                let stapler = crate::stapling::Stapler::new()?;
                stapler.staple_path(&args.path)?;
            }
        }
    }

    Ok(())
}

#[cfg(feature = "notarize")]
#[derive(Parser)]
struct NotaryWait {
    /// Maximum time in seconds to wait for the upload result
    #[arg(long, default_value = "600")]
    max_wait_seconds: u64,

    /// The ID of the previous submission to wait on
    submission_id: String,

    #[command(flatten)]
    api: NotaryApi,
}

#[cfg(feature = "notarize")]
fn command_notary_wait(args: &NotaryWait) -> Result<(), AppleCodesignError> {
    let wait_duration = std::time::Duration::from_secs(args.max_wait_seconds);
    let notarizer = args.api.notarizer()?;

    notarizer.wait_on_notarization_and_fetch_log(&args.submission_id, wait_duration)?;

    Ok(())
}

#[derive(Parser)]
struct ParseCodeSigningRequirement {
    /// Output format
    #[arg(long, value_parser = ["csrl", "expression-tree"], default_value = "csrl")]
    format: String,

    /// Path to file to parse
    input_path: PathBuf,
}

fn command_parse_code_signing_requirement(
    args: &ParseCodeSigningRequirement,
) -> Result<(), AppleCodesignError> {
    let data = std::fs::read(&args.input_path)?;

    let requirements = CodeRequirements::parse_blob(&data)?.0;

    for requirement in requirements.iter() {
        match args.format.as_str() {
            "csrl" => {
                println!("{requirement}");
            }
            "expression-tree" => {
                println!("{requirement:#?}");
            }
            format => panic!("unhandled format: {format}"),
        }
    }

    Ok(())
}

#[derive(Parser)]
struct PrintSignatureInfo {
    /// Filesystem path to entity whose info to print
    path: PathBuf,
}

fn command_print_signature_info(args: &PrintSignatureInfo) -> Result<(), AppleCodesignError> {
    let reader = SignatureReader::from_path(&args.path)?;

    let entities = reader.entities()?;
    serde_yaml::to_writer(std::io::stdout(), &entities)?;

    Ok(())
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct SessionJoinString {
    /// Open an editor to input the session join string
    #[arg(long = "editor")]
    session_join_string_editor: bool,

    /// Path to file containing session join string
    #[arg(long = "sjs-path")]
    session_join_string_path: Option<String>,

    /// Session join string (provided by the signing initiator)
    session_join_string: Option<String>,
}

#[derive(Parser)]
struct RemoteSign {
    #[command(flatten)]
    session_join_string: SessionJoinString,

    #[command(flatten)]
    certificate: CertificateSource,
}

fn command_remote_sign(args: &RemoteSign) -> Result<(), AppleCodesignError> {
    let session_join_string = if args.session_join_string.session_join_string_editor {
        let mut value = None;

        for _ in 0..3 {
            if let Some(content) = dialoguer::Editor::new()
                .require_save(true)
                .edit("# Please enter the -----BEGIN SESSION JOIN STRING---- content below.\n# Remember to save the file!")?
            {
                value = Some(content);
                break;
            }
        }

        value.ok_or_else(|| {
            AppleCodesignError::CliGeneralError("session join string not entered in editor".into())
        })?
    } else if let Some(path) = &args.session_join_string.session_join_string_path {
        std::fs::read_to_string(path)?
    } else if let Some(value) = &args.session_join_string.session_join_string {
        value.to_string()
    } else {
        return Err(AppleCodesignError::CliGeneralError(
            "session join string argument parsing failure".into(),
        ));
    };

    let mut joiner = create_session_joiner(session_join_string)?;

    if let Some(env) = &args.certificate.remote_shared_secret_env {
        let secret = std::env::var(env).map_err(|_| AppleCodesignError::CliBadArgument)?;
        joiner.register_state(SessionJoinState::SharedSecret(secret.as_bytes().to_vec()))?;
    } else if let Some(secret) = &args.certificate.remote_shared_secret {
        joiner.register_state(SessionJoinState::SharedSecret(secret.as_bytes().to_vec()))?;
    }

    let (private_keys, mut public_certificates) = args.certificate.resolve_certificates(true)?;

    let private = private_keys
        .into_iter()
        .next()
        .ok_or(AppleCodesignError::NoSigningCertificate)?;

    let cert = public_certificates.remove(0);

    let certificates = if let Some(chain) = cert.apple_root_certificate_chain() {
        // The chain starts with self.
        chain.into_iter().skip(1).collect::<Vec<_>>()
    } else {
        public_certificates
    };

    joiner.register_state(SessionJoinState::PublicKeyDecrypt(
        private.to_public_key_peer_decrypt()?,
    ))?;

    let client = UnjoinedSigningClient::new_signer(
        joiner,
        private.as_key_info_signer(),
        cert,
        certificates,
        args.certificate.remote_signing_url.clone(),
    )?;
    client.run()?;

    Ok(())
}

#[derive(Parser)]
struct Sign {
    /// Identifier string for binary. The value normally used by CFBundleIdentifier
    #[arg(long)]
    binary_identifier: Vec<String>,

    /// Path to a file containing binary code requirements data to be used as designated requirements
    #[arg(long)]
    code_requirements_path: Vec<String>,

    /// Path to an XML plist file containing code resources
    #[arg(long)]
    code_resources: Vec<String>,

    /// Code signature flags to set
    #[arg(long, value_parser = CodeSignatureFlags::all_user_configurable())]
    code_signature_flags: Vec<String>,

    /// Digest algorithm to use
    #[arg(long)]
    digest: Option<DigestType>,

    /// Extra digests to include in signatures
    #[arg(long, value_parser = SUPPORTED_HASHES)]
    extra_digest: Vec<String>,

    /// Path to a plist file containing entitlements
    #[arg(short = 'e', long)]
    entitlements_xml_path: Vec<String>,

    /// Hardened runtime version to use (defaults to SDK version used to build binary)
    #[arg(long)]
    runtime_version: Vec<String>,

    /// Path to an Info.plist file whose digest to include in Mach-O signature
    #[arg(long)]
    info_plist_path: Vec<String>,

    /// Team name/identifier to include in code signature
    #[arg(long)]
    team_name: Option<String>,

    /// URL of timestamp server to use to obtain a token of the CMS signature
    #[arg(long, default_value = APPLE_TIMESTAMP_URL)]
    timestamp_url: String,

    /// Glob expression of paths to exclude from signing
    #[arg(long)]
    exclude: Vec<String>,

    /// Path to Mach-O binary to sign
    input_path: PathBuf,

    /// Path to signed Mach-O binary to write
    output_path: Option<PathBuf>,

    #[command(flatten)]
    certificate: CertificateSource,
}

fn command_sign(args: &Sign) -> Result<(), AppleCodesignError> {
    let mut settings = SigningSettings::default();

    let (private_keys, mut public_certificates) = args.certificate.resolve_certificates(true)?;

    if private_keys.len() > 1 {
        error!("at most 1 PRIVATE KEY can be present; aborting");
        return Err(AppleCodesignError::CliBadArgument);
    }

    let private = if private_keys.is_empty() {
        None
    } else {
        Some(&private_keys[0])
    };

    if let Some(signing_key) = &private {
        if public_certificates.is_empty() {
            error!("a PRIVATE KEY requires a corresponding CERTIFICATE to pair with it");
            return Err(AppleCodesignError::CliBadArgument);
        }

        let cert = public_certificates.remove(0);

        warn!("registering signing key");
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

        if args.timestamp_url != "none" {
            warn!("using time-stamp protocol server {}", args.timestamp_url);
            settings.set_time_stamp_url(&args.timestamp_url)?;
        }
    }

    if let Some(team_id) = settings.set_team_id_from_signing_certificate() {
        warn!(
            "automatically setting team ID from signing certificate: {}",
            team_id
        );
    }

    for cert in public_certificates {
        warn!("registering extra X.509 certificate");
        settings.chain_certificate(cert);
    }

    if let Some(team_name) = &args.team_name {
        settings.set_team_id(team_name);
    }

    if let Some(value) = &args.digest {
        settings.set_digest_type(*value);
    }

    for value in &args.extra_digest {
        let (scope, digest_type) = parse_scoped_value(value)?;
        let digest_type = DigestType::try_from(digest_type)?;
        settings.add_extra_digest(scope, digest_type);
    }

    for pattern in &args.exclude {
        settings.add_path_exclusion(pattern)?;
    }

    for value in &args.binary_identifier {
        let (scope, identifier) = parse_scoped_value(value)?;
        settings.set_binary_identifier(scope, identifier);
    }

    for value in &args.code_requirements_path {
        let (scope, path) = parse_scoped_value(value)?;

        let code_requirements_data = std::fs::read(path)?;
        let reqs = CodeRequirements::parse_blob(&code_requirements_data)?.0;
        for expr in reqs.iter() {
            warn!(
                "setting designated code requirements for {}: {}",
                scope, expr
            );
            settings.set_designated_requirement_expression(scope.clone(), expr)?;
        }
    }

    for value in &args.code_resources {
        let (scope, path) = parse_scoped_value(value)?;

        warn!(
            "setting code resources data for {} from path {}",
            scope, path
        );
        let code_resources_data = std::fs::read(path)?;
        settings.set_code_resources_data(scope, code_resources_data);
    }

    for value in &args.code_signature_flags {
        let (scope, value) = parse_scoped_value(value)?;

        let flags = CodeSignatureFlags::from_str(value)?;
        settings.set_code_signature_flags(scope, flags);
    }

    for value in &args.entitlements_xml_path {
        let (scope, path) = parse_scoped_value(value)?;

        warn!("setting entitlments XML for {} from path {}", scope, path);
        let entitlements_data = std::fs::read_to_string(path)?;
        settings.set_entitlements_xml(scope, entitlements_data)?;
    }

    for value in &args.runtime_version {
        let (scope, value) = parse_scoped_value(value)?;

        let version = semver::Version::parse(value)?;
        settings.set_runtime_version(scope, version);
    }

    for value in &args.info_plist_path {
        let (scope, value) = parse_scoped_value(value)?;

        let content = std::fs::read(value)?;
        settings.set_info_plist_data(scope, content);
    }

    let signer = UnifiedSigner::new(settings);

    if let Some(output_path) = &args.output_path {
        warn!(
            "signing {} to {}",
            args.input_path.display(),
            output_path.display()
        );
        signer.sign_path(&args.input_path, output_path)?;
    } else {
        warn!("signing {} in place", args.input_path.display());
        signer.sign_path_in_place(&args.input_path)?;
    }

    if let Some(private) = &private {
        private.finish()?;
    }

    Ok(())
}

#[cfg(feature = "yubikey")]
fn command_smartcard_scan() -> Result<(), AppleCodesignError> {
    let mut ctx = ::yubikey::reader::Context::open()?;
    for (index, reader) in ctx.iter()?.enumerate() {
        println!("Device {}: {}", index, reader.name());

        if let Ok(yk) = reader.open() {
            let mut yk = crate::yubikey::YubiKey::from(yk);
            println!("Device {}: Serial: {}", index, yk.inner()?.serial());
            println!("Device {}: Version: {}", index, yk.inner()?.version());

            for (slot, cert) in yk.find_certificates()? {
                println!(
                    "Device {}: Certificate in slot {:?} / {}",
                    index,
                    slot,
                    hex::encode([u8::from(slot)])
                );
                print_certificate_info(&cert)?;
                println!();
            }
        }
    }

    Ok(())
}

#[cfg(not(feature = "yubikey"))]
fn command_smartcard_scan() -> Result<(), AppleCodesignError> {
    eprintln!("smartcard reading requires the `yubikey` crate feature, which isn't enabled.");
    eprintln!("recompile the crate with `cargo build --features yubikey` to enable support");
    std::process::exit(1);
}

#[derive(Parser)]
struct SmartcardGenerateKey {
    /// Smartcard slot number to store key in (9c is common)
    #[arg(long)]
    smartcard_slot: String,

    #[command(flatten)]
    policy: YubikeyPolicy,
}

#[cfg(feature = "yubikey")]
fn command_smartcard_generate_key(args: &SmartcardGenerateKey) -> Result<(), AppleCodesignError> {
    let slot_id = ::yubikey::piv::SlotId::from_str(&args.smartcard_slot)?;

    let touch_policy = str_to_touch_policy(args.policy.touch_policy.as_str())?;
    let pin_policy = str_to_pin_policy(args.policy.pin_policy.as_str())?;

    let mut yk = YubiKey::new()?;
    yk.set_pin_callback(prompt_smartcard_pin);

    yk.generate_key(slot_id, touch_policy, pin_policy)?;

    Ok(())
}

#[cfg(not(feature = "yubikey"))]
fn command_smartcard_generate_key(_args: &SmartcardGenerateKey) -> Result<(), AppleCodesignError> {
    eprintln!("smartcard integration requires the `yubikey` crate feature, which isn't enabled.");
    eprintln!("recompile the crate with `cargo build --features yubikey` to enable support");
    std::process::exit(1);
}

#[derive(Parser)]
struct SmartcardImport {
    /// Re-use the existing private key in the smartcard slot
    #[arg(long)]
    existing_key: bool,

    /// Don't actually perform the import
    #[arg(long)]
    dry_run: bool,

    #[command(flatten)]
    certificate: CertificateSource,

    #[command(flatten)]
    policy: YubikeyPolicy,
}

#[cfg(feature = "yubikey")]
fn command_smartcard_import(args: &SmartcardImport) -> Result<(), AppleCodesignError> {
    let (keys, certs) = args.certificate.resolve_certificates(false)?;

    let slot_id = ::yubikey::piv::SlotId::from_str(
        args.certificate.smartcard_slot.as_ref().ok_or_else(|| {
            error!("--smartcard-slot is required");
            AppleCodesignError::CliBadArgument
        })?,
    )?;
    let touch_policy = str_to_touch_policy(args.policy.touch_policy.as_str())?;
    let pin_policy = str_to_pin_policy(args.policy.pin_policy.as_str())?;

    println!(
        "found {} private keys and {} public certificates",
        keys.len(),
        certs.len()
    );

    let key = if args.existing_key {
        println!("using existing private key in smartcard");

        if !keys.is_empty() {
            println!(
                "ignoring {} private keys specified via arguments",
                keys.len()
            );
        }

        None
    } else {
        Some(keys.into_iter().next().ok_or_else(|| {
            println!("no private key found");
            AppleCodesignError::CliBadArgument
        })?)
    };

    let cert = certs.into_iter().next().ok_or_else(|| {
        println!("no public certificates found");
        AppleCodesignError::CliBadArgument
    })?;

    println!(
        "Will import the following certificate into slot {}",
        hex::encode([u8::from(slot_id)])
    );
    print_certificate_info(&cert)?;

    let mut yk = YubiKey::new()?;
    yk.set_pin_callback(prompt_smartcard_pin);

    if args.dry_run {
        println!("dry run mode enabled; stopping");
        return Ok(());
    }

    if let Some(key) = key {
        yk.import_key(
            slot_id,
            key.as_key_info_signer(),
            &cert,
            touch_policy,
            pin_policy,
        )?;
    } else {
        yk.import_certificate(slot_id, &cert)?;
    }

    Ok(())
}

#[cfg(not(feature = "yubikey"))]
fn command_smartcard_import(_args: &SmartcardImport) -> Result<(), AppleCodesignError> {
    eprintln!("smartcard import requires `yubikey` crate feature, which isn't enabled.");
    eprintln!("recompile the crate with `cargo build --features yubikey` to enable support");
    std::process::exit(1);
}

#[derive(Parser)]
struct Staple {
    /// Path to entity to attempt to staple
    path: PathBuf,
}

fn command_staple(args: &Staple) -> Result<(), AppleCodesignError> {
    let stapler = crate::stapling::Stapler::new()?;
    stapler.staple_path(&args.path)?;

    Ok(())
}

#[derive(Parser)]
struct Verify {
    /// Path of Mach-O binary to examine
    path: PathBuf,
}

fn command_verify(args: &Verify) -> Result<(), AppleCodesignError> {
    let data = std::fs::read(&args.path)?;

    let problems = crate::verify::verify_macho_data(data);

    for problem in &problems {
        println!("{problem}");
    }

    if problems.is_empty() {
        eprintln!("no problems detected!");
        eprintln!("(we do not verify everything so please do not assume that the signature meets Apple standards)");
        Ok(())
    } else {
        Err(AppleCodesignError::VerificationProblems)
    }
}

fn command_x509_oids() -> Result<(), AppleCodesignError> {
    println!("# Extended Key Usage (EKU) Extension OIDs");
    println!();
    for ekup in crate::certificate::ExtendedKeyUsagePurpose::all() {
        println!("{}\t{:?}", ekup.as_oid(), ekup);
    }
    println!();
    println!("# Code Signing Certificate Extension OIDs");
    println!();
    for ext in crate::certificate::CodeSigningCertificateExtension::all() {
        println!("{}\t{:?}", ext.as_oid(), ext);
    }
    println!();
    println!("# Certificate Authority Certificate Extension OIDs");
    println!();
    for ext in crate::certificate::CertificateAuthorityExtension::all() {
        println!("{}\t{:?}", ext.as_oid(), ext);
    }

    Ok(())
}

#[derive(Subcommand)]
enum Subcommands {
    /// Analyze an X.509 certificate for Apple code signing properties.
    ///
    /// Given the path to a PEM encoded X.509 certificate, this command will read
    /// the certificate and print information about it relevant to Apple code
    /// signing.
    ///
    /// The output of the command can be useful to learn about X.509 certificate
    /// extensions used by code signing certificates and to debug low-level
    /// properties related to certificates.
    AnalyzeCertificate(AnalyzeCertificate),

    /// Compute code hashes for a binary
    ComputeCodeHashes(ComputeCodeHashes),

    /// Print a diff between the signature content of two paths
    DiffSignatures(DiffSignatures),

    /// Encode App Store Connect API Key metadata to a single file
    #[cfg(feature = "notarize")]
    #[command(long_about = ENCODE_APP_STORE_CONNECT_API_KEY_ABOUT)]
    EncodeAppStoreConnectApiKey(EncodeAppStoreConnectApiKey),

    /// Extracts code signature data from a Mach-O binary
    #[command(long_about = EXTRACT_ABOUT)]
    Extract(Extract),

    /// Generates a certificate signing request that can be sent to Apple and exchanged for a signing certificate
    GenerateCertificateSigningRequest(GenerateCertificateSigningRequest),

    /// Generate a self-signed certificate for code signing
    #[command(long_about = GENERATE_SELF_SIGNED_CERTIFICATE_ABOUT)]
    GenerateSelfSignedCertificate(GenerateSelfSignedCertificate),

    /// Export Apple CA certificates from the macOS Keychain
    KeychainExportCertificateChain(KeychainExportCertificateChain),

    /// Print information about certificates in the macOS keychain
    KeychainPrintCertificates(KeychainPrintCertificates),

    #[cfg(feature = "notarize")]
    /// Fetch the notarization log for a previous submission
    NotaryLog(NotaryLog),

    /// Upload an asset to Apple for notarization and possibly staple it
    #[cfg(feature = "notarize")]
    #[command(long_about = NOTARIZE_ABOUT, alias = "notarize")]
    NotarySubmit(NotarySubmit),

    /// Wait for completion of a previous submission
    #[cfg(feature = "notarize")]
    NotaryWait(NotaryWait),

    /// Parse binary Code Signing Requirement data into a human readable string
    #[command(long_about = PARSE_CODE_SIGNING_REQUIREMENT_ABOUT)]
    ParseCodeSigningRequirement(ParseCodeSigningRequirement),

    /// Print signature information for a filesystem path
    PrintSignatureInfo(PrintSignatureInfo),

    /// Create signatures initiated from a remote signing operation
    RemoteSign(RemoteSign),

    /// Sign a Mach-O binary or bundle
    #[command(long_about = SIGN_ABOUT)]
    Sign(Sign),

    /// Generate a new private key on a smartcard
    SmartcardGenerateKey(SmartcardGenerateKey),

    /// Import a code signing certificate and key into a smartcard
    SmartcardImport(SmartcardImport),

    /// Show information about available smartcard (SC) devices
    SmartcardScan,

    /// Staples a notarization ticket to an entity
    Staple(Staple),

    /// Verifies code signature data
    Verify(Verify),

    /// Print information about X.509 OIDs related to Apple code signing
    X509Oids,
}

/// Sign and notarize Apple programs. See https://gregoryszorc.com/docs/apple-codesign/main/ for more docs
#[derive(Parser)]
#[command(author, version, arg_required_else_help = true)]
struct Cli {
    /// Increase logging verbosity. Can be specified multiple times
    #[arg(short = 'v', long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Subcommands,
}

pub fn main_impl() -> Result<(), AppleCodesignError> {
    let cli = Cli::parse();

    // TODO make default log level warn once we audit logging sites.
    let log_level = match cli.verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(log_level.as_str()),
    );

    // Disable log context except at higher log levels.
    if log_level <= LevelFilter::Info {
        builder
            .format_timestamp(None)
            .format_level(false)
            .format_target(false);
    }

    // This spews unwanted output at default level. Nerf it by default.
    if log_level == LevelFilter::Info {
        builder.filter_module("rustls", LevelFilter::Error);
    }

    builder.init();

    match &cli.command {
        Subcommands::AnalyzeCertificate(args) => command_analyze_certificate(args),
        Subcommands::ComputeCodeHashes(args) => command_compute_code_hashes(args),
        Subcommands::DiffSignatures(args) => command_diff_signatures(args),
        #[cfg(feature = "notarize")]
        Subcommands::EncodeAppStoreConnectApiKey(args) => {
            command_encode_app_store_connect_api_key(args)
        }
        Subcommands::Extract(args) => command_extract(args),
        Subcommands::GenerateCertificateSigningRequest(args) => {
            command_generate_certificate_signing_request(args)
        }
        Subcommands::GenerateSelfSignedCertificate(args) => {
            command_generate_self_signed_certificate(args)
        }
        Subcommands::KeychainExportCertificateChain(args) => {
            command_keychain_export_certificate_chain(args)
        }
        Subcommands::KeychainPrintCertificates(args) => command_keychain_print_certificates(args),
        #[cfg(feature = "notarize")]
        Subcommands::NotaryLog(args) => command_notary_log(args),
        #[cfg(feature = "notarize")]
        Subcommands::NotarySubmit(args) => command_notary_submit(args),
        #[cfg(feature = "notarize")]
        Subcommands::NotaryWait(args) => command_notary_wait(args),
        Subcommands::ParseCodeSigningRequirement(args) => {
            command_parse_code_signing_requirement(args)
        }
        Subcommands::PrintSignatureInfo(args) => command_print_signature_info(args),
        Subcommands::RemoteSign(args) => command_remote_sign(args),
        Subcommands::Sign(args) => command_sign(args),
        Subcommands::SmartcardGenerateKey(args) => command_smartcard_generate_key(args),
        Subcommands::SmartcardImport(args) => command_smartcard_import(args),
        Subcommands::SmartcardScan => command_smartcard_scan(),
        Subcommands::Staple(args) => command_staple(args),
        Subcommands::Verify(args) => command_verify(args),
        Subcommands::X509Oids => command_x509_oids(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}
