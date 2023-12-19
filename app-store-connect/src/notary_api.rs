// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! App Store Connect Notary API.
//!
//! See also <https://developer.apple.com/documentation/notaryapi>.

use {
    crate::{AppStoreConnectClient, Result},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    thiserror::Error,
};

pub const APPLE_NOTARY_SUBMIT_SOFTWARE_URL: &str =
    "https://appstoreconnect.apple.com/notary/v2/submissions";

/// A notification that the notary service sends you when notarization finishes.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSubmissionRequestNotification {
    pub channel: String,
    pub target: String,
}

/// Data that you provide when starting a submission to the notary service.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSubmissionRequest {
    pub notifications: Vec<NewSubmissionRequestNotification>,
    pub sha256: String,
    pub submission_name: String,
}

/// Information that you use to upload your software for notarization.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSubmissionResponseDataAttributes {
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub aws_session_token: String,
    pub bucket: String,
    pub object: String,
}

/// Information that the notary service provides for uploading your software for notarization and
/// tracking the submission.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSubmissionResponseData {
    pub attributes: NewSubmissionResponseDataAttributes,
    pub id: String,
    pub r#type: String,
}

/// The notary service’s response to a software submission.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSubmissionResponse {
    pub data: NewSubmissionResponseData,
    pub meta: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum SubmissionResponseStatus {
    Accepted,
    #[serde(rename = "In Progress")]
    InProgress,
    Invalid,
    Rejected,
    #[serde(other)]
    Unknown,
}

impl std::fmt::Display for SubmissionResponseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::Accepted => "accepted",
            Self::InProgress => "in progress",
            Self::Invalid => "invalid",
            Self::Rejected => "rejected",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Information about the status of a submission.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionResponseDataAttributes {
    pub created_date: String,
    pub name: String,
    pub status: SubmissionResponseStatus,
}

/// Information that the service provides about the status of a notarization submission.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionResponseData {
    pub attributes: SubmissionResponseDataAttributes,
    pub id: String,
    pub r#type: String,
}

/// The notary service’s response to a request for the status of a submission.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionResponse {
    pub data: SubmissionResponseData,
    pub meta: Value,
}

impl SubmissionResponse {
    /// Convert the instance into a [Result].
    ///
    /// Will yield [Err] if the notarization/upload was not successful.
    pub fn into_result(self) -> Result<Self> {
        match self.data.attributes.status {
            SubmissionResponseStatus::Accepted => Ok(self),
            status => Err(NotarizationError(status).into()),
        }
    }
}

/// The notary service’s response to a request for the list of submissions.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSubmissionResponse {
    pub data: Vec<SubmissionResponseData>,
    pub meta: Value,
}

#[derive(Clone, Copy, Debug, Error)]
#[error("notarization {0}")]
pub struct NotarizationError(SubmissionResponseStatus);

/// Information about the log associated with the submission.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionLogResponseDataAttributes {
    pub developer_log_url: String,
}

/// Data that indicates how to get the log information for a particular submission.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionLogResponseData {
    pub attributes: SubmissionLogResponseDataAttributes,
    pub id: String,
    pub r#type: String,
}

/// The notary service’s response to a request for the log information about a completed submission.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionLogResponse {
    pub data: SubmissionLogResponseData,
    pub meta: Value,
}

impl AppStoreConnectClient {
    /// Create a submission to the Notary API.
    pub fn create_submission(
        &self,
        sha256: &str,
        submission_name: &str,
    ) -> Result<NewSubmissionResponse> {
        let token = self.get_token()?;

        let body = NewSubmissionRequest {
            notifications: Vec::new(),
            sha256: sha256.to_string(),
            submission_name: submission_name.to_string(),
        };
        let req = self
            .client
            .post(APPLE_NOTARY_SUBMIT_SOFTWARE_URL)
            .bearer_auth(token)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body);

        Ok(self.send_request(req)?.json()?)
    }

    /// Fetch the status of a Notary API submission.
    pub fn get_submission(&self, submission_id: &str) -> Result<SubmissionResponse> {
        let token = self.get_token()?;

        let req = self
            .client
            .get(format!(
                "{APPLE_NOTARY_SUBMIT_SOFTWARE_URL}/{submission_id}"
            ))
            .bearer_auth(token)
            .header("Accept", "application/json");

        Ok(self.send_request(req)?.json()?)
    }

    pub fn list_submissions(&self) -> Result<ListSubmissionResponse> {
        let token = self.get_token()?;
        let req = self
            .client
            .get(APPLE_NOTARY_SUBMIT_SOFTWARE_URL)
            .bearer_auth(token)
            .header("Accept", "application/json");

        Ok(self.send_request(req)?.json()?)
    }

    /// Fetch details about a single completed notarization.
    pub fn get_submission_log(&self, submission_id: &str) -> Result<Value> {
        let token = self.get_token()?;

        let req = self
            .client
            .get(format!(
                "{APPLE_NOTARY_SUBMIT_SOFTWARE_URL}/{submission_id}/logs"
            ))
            .bearer_auth(token)
            .header("Accept", "application/json");

        let res: SubmissionLogResponse = self.send_request(req)?.json()?;

        let url = res.data.attributes.developer_log_url;
        let logs = self.client.get(url).send()?.json::<Value>()?;

        Ok(logs)
    }
}
