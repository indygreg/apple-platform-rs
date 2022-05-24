//! Data structures in Apple SDKs.

use {serde::Deserialize, std::collections::HashMap};

/// Represents the DefaultProperties key in a SDKSettings.json file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct SdkSettingsJsonDefaultProperties {
    pub platform_name: String,
}

/// Represents a SupportedTargets value in a SDKSettings.json file.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AppleSdkSupportedTarget {
    /// Names of machine architectures that can be targeted.
    ///
    /// e.g. `x86_64`, `arm64`, `arm64e`.
    pub archs: Vec<String>,

    /// Default deployment target version.
    ///
    /// Likely corresponds to the OS version this SDK is associated with.
    /// e.g. the macOS 12.3 SDK would target `12.3` by default.
    pub default_deployment_target: String,

    /// The name of the settings variant to use by default.
    pub default_variant: Option<String>,

    /// The name of the toolchain setting that influences which deployment target version is used.
    ///
    /// e.g. on macOS this will be `MACOSX_DEPLOYMENT_TARGET`. This represents an
    /// environment variable that can be set to influence which deployment target
    /// version to use.
    pub deployment_target_setting_name: Option<String>,

    /// The lowest version of a platform that this SDK can target.
    ///
    /// Using this SDK, it is possible to emit code that will support running
    /// down to the OS version specified by this value. e.g. `10.9` is a
    /// common value for macOS SDKs.
    pub minimum_deployment_target: String,

    /// A name given to the platform.
    ///
    /// e.g. `macOS`.
    pub platform_family_name: Option<String>,

    /// List of platform versions that this SDK can target.
    ///
    /// This is likely a range of all major versions between `minimum_deployment_target`
    /// and `default_deployment_target`.
    pub valid_deployment_targets: Vec<String>,
}

/// Used for deserializing a SDKSettings.json file in an SDK directory.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SdkSettingsJson {
    pub canonical_name: String,
    pub default_deployment_target: String,
    pub default_properties: SdkSettingsJsonDefaultProperties,
    pub default_variant: Option<String>,
    pub display_name: String,
    pub maximum_deployment_target: String,
    pub minimal_display_name: String,
    pub supported_targets: HashMap<String, AppleSdkSupportedTarget>,
    pub version: String,
}
