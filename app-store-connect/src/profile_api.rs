// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{AppStoreConnectClient, Result};
use serde::{Deserialize, Serialize};

const APPLE_CERTIFICATE_URL: &str = "https://api.appstoreconnect.apple.com/v1/profiles";

impl AppStoreConnectClient {
    pub fn create_profile(
        &self,
        name: &str,
        profile_type: ProfileType,
        bundle_id: &str,
        certificates: &[String],
        devices: Option<&[String]>,
    ) -> Result<ProfileResponse> {
        let token = self.get_token()?;
        let body = ProfileCreateRequest {
            data: ProfileCreateRequestData {
                attributes: ProfileCreateRequestAttributes {
                    name: name.into(),
                    profile_type: profile_type.to_string(),
                },
                relationships: ProfileCreateRequestRelationships {
                    bundle_id: Ref {
                        data: RefData {
                            id: bundle_id.into(),
                            r#type: "bundleIds".into(),
                        },
                    },
                    certificates: Refs {
                        data: certificates
                            .iter()
                            .map(|certificate| RefData {
                                id: certificate.into(),
                                r#type: "certificates".into(),
                            })
                            .collect(),
                    },
                    devices: devices.map(|devices| Refs {
                        data: devices
                            .iter()
                            .map(|device| RefData {
                                id: device.into(),
                                r#type: "devices".into(),
                            })
                            .collect(),
                    }),
                },
                r#type: "profiles".into(),
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

    pub fn list_profiles(&self) -> Result<ProfilesResponse> {
        let token = self.get_token()?;
        let req = self
            .client
            .get(APPLE_CERTIFICATE_URL)
            .bearer_auth(token)
            .header("Accept", "application/json");
        Ok(self.send_request(req)?.json()?)
    }

    pub fn get_profile(&self, id: &str) -> Result<ProfileResponse> {
        let token = self.get_token()?;
        let req = self
            .client
            .get(format!("{APPLE_CERTIFICATE_URL}/{id}"))
            .bearer_auth(token)
            .header("Accept", "application/json");
        Ok(self.send_request(req)?.json()?)
    }

    pub fn delete_profile(&self, id: &str) -> Result<()> {
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
pub struct ProfileCreateRequest {
    pub data: ProfileCreateRequestData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileCreateRequestData {
    pub attributes: ProfileCreateRequestAttributes,
    pub relationships: ProfileCreateRequestRelationships,
    pub r#type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileCreateRequestAttributes {
    pub name: String,
    pub profile_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileCreateRequestRelationships {
    pub bundle_id: Ref,
    pub certificates: Refs,
    pub devices: Option<Refs>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ref {
    pub data: RefData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Refs {
    pub data: Vec<RefData>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefData {
    pub id: String,
    pub r#type: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum ProfileType {
    IosAppDevelopment,
    MacAppDevelopment,
    IosAppStore,
    MacAppStore,
    MacAppDirect,
}

impl std::fmt::Display for ProfileType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::IosAppDevelopment => "IOS_APP_DEVELOPMENT",
            Self::MacAppDevelopment => "MAC_APP_DEVELOPMENT",
            Self::IosAppStore => "IOS_APP_STORE",
            Self::MacAppStore => "MAC_APP_STORE",
            Self::MacAppDirect => "MAC_APP_DIRECT",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileResponse {
    pub data: Profile,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfilesResponse {
    pub data: Vec<Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub attributes: ProfileAttributes,
    pub id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileAttributes {
    pub name: String,
    pub platform: String,
    pub profile_content: String,
    pub uuid: String,
    pub created_date: String,
    pub profile_state: String,
    pub profile_type: String,
    pub expiration_date: String,
}
