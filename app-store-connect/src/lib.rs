// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod api_key;
mod api_token;
pub mod bundle_api;
pub mod certs_api;
pub mod cli;
pub mod device_api;
pub mod notary_api;
pub mod profile_api;

use {
    reqwest::blocking::{Client, ClientBuilder, RequestBuilder, Response},
    serde_json::Value,
    std::{path::Path, sync::Mutex},
    thiserror::Error,
};

pub use crate::api_key::{InvalidPemPrivateKey, UnifiedApiKey};
pub use crate::api_token::{AppStoreConnectToken, ConnectTokenEncoder, MissingApiKey};

pub type Result<T> = anyhow::Result<T>;

/// A client for App Store Connect API.
///
/// The client isn't generic. Don't get any ideas.
pub struct AppStoreConnectClient {
    client: Client,
    connect_token: ConnectTokenEncoder,
    token: Mutex<Option<AppStoreConnectToken>>,
}

impl AppStoreConnectClient {
    pub fn from_json_path(path: &Path) -> Result<Self> {
        let key = UnifiedApiKey::from_json_path(path)?;
        AppStoreConnectClient::new(key.try_into()?)
    }

    /// Create a new client to the App Store Connect API.
    pub fn new(connect_token: ConnectTokenEncoder) -> Result<Self> {
        let client = ClientBuilder::default()
            .user_agent("asconnect crate (https://crates.io/crates/asconnect)")
            .build()?;
        Ok(Self {
            client,
            connect_token,
            token: Mutex::new(None),
        })
    }

    pub fn get_token(&self) -> Result<String> {
        let mut token = self.token.lock().unwrap();

        // TODO need to handle token expiration.
        if token.is_none() {
            token.replace(self.connect_token.new_token(300)?);
        }

        Ok(token.as_ref().unwrap().clone())
    }

    pub fn send_request(&self, request: RequestBuilder) -> Result<Response> {
        let request = request.build()?;
        let method = request.method().to_string();
        let url = request.url().to_string();

        log::debug!("{} {}", request.method(), url);

        let response = self.client.execute(request)?;

        if response.status().is_success() {
            Ok(response)
        } else {
            let body = response.bytes()?;

            let message = if let Ok(value) = serde_json::from_slice::<Value>(body.as_ref()) {
                serde_json::to_string_pretty(&value)?
            } else {
                String::from_utf8_lossy(body.as_ref()).into()
            };

            Err(AppStoreConnectError {
                method,
                url,
                message,
            }
            .into())
        }
    }
}

#[derive(Clone, Debug, Error)]
#[error("appstore connect error:\n{method} {url}\n{message}")]
pub struct AppStoreConnectError {
    method: String,
    url: String,
    message: String,
}
