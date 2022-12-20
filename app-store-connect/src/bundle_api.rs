// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{AppStoreConnectClient, Result};
use serde::{Deserialize, Serialize};

const APPLE_CERTIFICATE_URL: &str = "https://api.appstoreconnect.apple.com/v1/bundleIds";

impl AppStoreConnectClient {
    pub fn register_bundle_id(&self, identifier: &str, name: &str) -> Result<BundleIdResponse> {
        let token = self.get_token()?;
        let body = BundleIdCreateRequest {
            data: BundleIdCreateRequestData {
                attributes: BundleIdCreateRequestAttributes {
                    identifier: identifier.into(),
                    name: name.into(),
                    platform: "UNIVERSAL".into(),
                },
                r#type: "bundleIds".into(),
            },
        };
        let req = self
            .client
            .post(APPLE_CERTIFICATE_URL)
            .bearer_auth(token)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body);
        Ok(self.send_request(req)?.json()?)
    }

    pub fn list_bundle_ids(&self) -> Result<BundleIdsResponse> {
        let token = self.get_token()?;
        let req = self
            .client
            .get(APPLE_CERTIFICATE_URL)
            .bearer_auth(token)
            .header("Accept", "application/json");
        Ok(self.send_request(req)?.json()?)
    }

    pub fn get_bundle_id(&self, id: &str) -> Result<BundleIdResponse> {
        let token = self.get_token()?;
        let req = self
            .client
            .get(format!("{APPLE_CERTIFICATE_URL}/{id}"))
            .bearer_auth(token)
            .header("Accept", "application/json");
        Ok(self.send_request(req)?.json()?)
    }

    pub fn delete_bundle_id(&self, id: &str) -> Result<()> {
        let token = self.get_token()?;
        let req = self
            .client
            .delete(format!("{APPLE_CERTIFICATE_URL}/{id}"))
            .bearer_auth(token);
        self.send_request(req)?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleIdCreateRequest {
    pub data: BundleIdCreateRequestData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleIdCreateRequestData {
    pub attributes: BundleIdCreateRequestAttributes,
    pub r#type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleIdCreateRequestAttributes {
    pub identifier: String,
    pub name: String,
    pub platform: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum BundleIdPlatform {
    Ios,
    MacOs,
}

impl std::fmt::Display for BundleIdPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::Ios => "IOS",
            Self::MacOs => "MAC_OS",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleIdResponse {
    pub data: BundleId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleIdsResponse {
    pub data: Vec<BundleId>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleId {
    pub attributes: BundleIdAttributes,
    pub id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleIdAttributes {
    pub identifier: String,
    pub name: String,
    pub platform: String,
    pub seed_id: String,
}
