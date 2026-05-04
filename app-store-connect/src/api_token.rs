// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! App Store Connect API tokens.

use {
    crate::Result,
    base64::{engine::general_purpose::STANDARD, Engine},
    jsonwebtoken::{Algorithm, EncodingKey, Header},
    reqwest::blocking::Client,
    serde::{Deserialize, Serialize},
    std::{path::Path, time::SystemTime},
    thiserror::Error,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ConnectTokenRequest {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
}

/// A JWT Token for use with App Store Connect API.
pub type AppStoreConnectToken = String;

/// A factory for App Store Connect API tokens.
///
/// Represents a private key used to create JWT tokens for use with App Store Connect.
///
/// See https://developer.apple.com/documentation/appstoreconnectapi/creating_api_keys_for_app_store_connect_api
/// and https://developer.apple.com/documentation/appstoreconnectapi/generating_tokens_for_api_requests
/// for more details.
///
/// This entity holds the necessary metadata to issue new JWT tokens.
///
/// App Store Connect API tokens/JWTs are derived from:
///
/// * A key identifier. This is a short alphanumeric string like `DEADBEEF42`.
/// * An issuer ID. This is likely a UUID.
/// * A private key. Likely ECDSA.
///
/// All these are issued by Apple. You can log in to App Store Connect and see/manage your keys
/// at https://appstoreconnect.apple.com/access/api.
#[derive(Clone)]
pub enum ConnectTokenEncoder {
    JwtEncodingKey {
        key_id: String,
        issuer_id: String,
        encoding_key: EncodingKey,
    },

    UsernamePassword {
        email: String,
        password: String,
        team_id: String,
    },
}

impl ConnectTokenEncoder {
    /// Construct an instance from a username, password and team ID.
    pub fn from_username_password(email: String, password: String, team_id: String) -> Self {
        Self::UsernamePassword {
            email,
            password,
            team_id,
        }
    }

    /// Construct an instance from an [EncodingKey] instance.
    ///
    /// This is the lowest level API and ultimately what all constructors use.
    pub fn from_jwt_encoding_key(
        key_id: String,
        issuer_id: String,
        encoding_key: EncodingKey,
    ) -> Self {
        Self::JwtEncodingKey {
            key_id,
            issuer_id,
            encoding_key,
        }
    }

    /// Construct an instance from a DER encoded ECDSA private key.
    pub fn from_ecdsa_der(key_id: String, issuer_id: String, der_data: &[u8]) -> Result<Self> {
        let encoding_key = EncodingKey::from_ec_der(der_data);

        Ok(Self::from_jwt_encoding_key(key_id, issuer_id, encoding_key))
    }

    /// Create a token from a PEM encoded ECDSA private key.
    pub fn from_ecdsa_pem(key_id: String, issuer_id: String, pem_data: &[u8]) -> Result<Self> {
        let encoding_key = EncodingKey::from_ec_pem(pem_data)?;

        Ok(Self::from_jwt_encoding_key(key_id, issuer_id, encoding_key))
    }

    /// Create a token from a PEM encoded ECDSA private key in a filesystem path.
    pub fn from_ecdsa_pem_path(
        key_id: String,
        issuer_id: String,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let data = std::fs::read(path.as_ref())?;

        Self::from_ecdsa_pem(key_id, issuer_id, &data)
    }

    /// Attempt to construct in instance from an API Key ID.
    ///
    /// e.g. `DEADBEEF42`. This looks for an `AuthKey_<id>.p8` file in default search
    /// locations like `~/.appstoreconnect/private_keys`.
    pub fn from_api_key_id(key_id: String, issuer_id: String) -> Result<Self> {
        let mut search_paths = vec![std::env::current_dir()?.join("private_keys")];

        if let Some(home) = dirs::home_dir() {
            search_paths.extend([
                home.join("private_keys"),
                home.join(".private_keys"),
                home.join(".appstoreconnect").join("private_keys"),
            ]);
        }

        // AuthKey_<apiKey>.p8
        let filename = format!("AuthKey_{key_id}.p8");

        for path in search_paths {
            let candidate = path.join(filename.as_str());

            if candidate.exists() {
                return Self::from_ecdsa_pem_path(key_id, issuer_id, candidate);
            }
        }

        Err(MissingApiKey.into())
    }

    /// Mint a new JWT token.
    ///
    /// Using the private key and key metadata bound to this instance, we issue a new JWT
    /// for the requested duration.
    pub fn new_token(&self, duration: u64) -> Result<AppStoreConnectToken> {
        match self {
            Self::JwtEncodingKey {
                key_id,
                issuer_id,
                encoding_key,
            } => {
                let header = Header {
                    kid: Some(key_id.clone()),
                    alg: Algorithm::ES256,
                    ..Default::default()
                };

                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("calculating UNIX time should never fail")
                    .as_secs();

                let claims = ConnectTokenRequest {
                    iss: issuer_id.clone(),
                    iat: now,
                    exp: now + duration,
                    aud: "appstoreconnect-v1".to_string(),
                };

                Ok(jsonwebtoken::encode(&header, &claims, encoding_key)?)
            }

            Self::UsernamePassword {
                email,
                password,
                team_id,
            } => Ok(fetch_token_asp(email, password, team_id)?),
        }
    }
}

#[derive(Clone, Copy, Debug, Error)]
#[error("no app store connect api key found")]
pub struct MissingApiKey;

/// Fetch an App Store Connect API token using a username, password and team ID.
///
/// Uses the `https://appstoreconnect.apple.com/notary/v2/asp` endpoint.
fn fetch_token_asp(email: &str, password: &str, team_id: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct AspResponse {
        data: AspData,
    }

    #[derive(Deserialize)]
    struct AspData {
        attributes: AspAttributes,
    }

    #[derive(Deserialize)]
    struct AspAttributes {
        token: String,
    }

    let res = Client::new()
        .get("https://appstoreconnect.apple.com/notary/v2/asp")
        .header("Accept", "application/json")
        .header("X-Developer-Team-ID", team_id)
        .header(
            "X-Developer-Authorization",
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", email, password))
            ),
        )
        .send()?
        .error_for_status()?
        .json::<AspResponse>()?;

    Ok(res.data.attributes.token)
}
