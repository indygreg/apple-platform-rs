//! Data structures in Apple SDKs.

use {
    crate::{Error, UnparsedSdk},
    serde::Deserialize,
    std::{
        collections::HashMap,
        path::{Path, PathBuf},
    },
};

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

/// An Apple SDK with parsed settings.
///
/// Unlike [AppleSdkDirectory], this type gives you access to rich metadata about the
/// Apple SDK. This includes things like targeting capabilities.
#[cfg(feature = "parse")]
#[derive(Clone, Debug)]
pub struct ParsedSdk {
    /// Root directory of the SDK.
    pub path: PathBuf,

    /// Whether the root directory is a symlink to another path.
    pub is_symlink: bool,

    /// The name of the platform.
    ///
    /// This is likely the part before the `*.platform` in the platform directory in which
    /// this SDK is located. e.g. `macosx`.
    pub platform_name: String,

    /// The canonical name of the SDK. e.g. `macosx12.3`.
    pub name: String,

    /// Version of the default deployment target for this SDK.
    ///
    /// This is likely the OS version the SDK came from. e.g. `12.3`.
    pub default_deployment_target: String,

    /// Name of default settings variant for this SDK.
    ///
    /// Some SDKs have named variants defining targeting settings. This field holds
    /// the name of the default variant.
    ///
    /// For example, macOS SDKs have a `macos` variant for targeting macOS and an
    /// `iosmac` variant for targeting iOS running on macOS.
    pub default_variant: Option<String>,

    /// Human friendly name of this SDK.
    ///
    /// e.g. `macOS 12.3`.
    pub display_name: String,

    /// Maximum deployment target version this SDK supports.
    ///
    /// This is a very string denoting the maximum version this SDK can target.
    /// e.g. a `12.3` would list `12.3.99`.
    pub maximum_deployment_target: String,

    /// Human friendly value for name (probably just version string).
    ///
    /// A shortened display name. e.g. `12.3`.
    pub minimal_display_name: String,

    /// Describes named target configurations this SDK supports.
    ///
    /// SDKs can have multiple named targets defining pre-canned default targeting
    /// settings. This field holds these data structures.
    ///
    /// Example keys are `macosx` and `iosmac`. Use the [Self::default_variant]
    /// field to access the default target.
    pub supported_targets: HashMap<String, AppleSdkSupportedTarget>,

    /// Version of this SDK. e.g. `12.3`.
    pub version: String,
}

#[cfg(feature = "parse")]
impl ParsedSdk {
    /// Attempt to resolve an SDK from a path to the SDK's root directory.
    pub fn from_directory(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();

        // Need to call symlink_metadata so symlinks aren't followed.
        let metadata = std::fs::symlink_metadata(path)?;

        let is_symlink = metadata.file_type().is_symlink();

        let json_path = path.join("SDKSettings.json");
        let plist_path = path.join("SDKSettings.plist");

        if json_path.exists() {
            let fh = std::fs::File::open(&path)?;
            let value: SdkSettingsJson = serde_json::from_reader(fh)?;

            Self::from_json(path.to_path_buf(), is_symlink, value)
        } else if plist_path.exists() {
            let value = plist::Value::from_file(&plist_path)?;

            Self::from_plist(path.to_path_buf(), is_symlink, value)
        } else {
            Err(Error::PathNotSdk(path.to_path_buf()))
        }
    }

    /// Construct an instance by parsing an `SDKSettings.json` file in a directory.
    ///
    /// These files are only available in more modern SDKs. For macOS, that's 10.14+.
    /// For more reliably SDK construction, use [Self::from_plist()].
    pub fn from_json(
        path: PathBuf,
        is_symlink: bool,
        value: SdkSettingsJson,
    ) -> Result<Self, Error> {
        Ok(Self {
            path,
            is_symlink,
            platform_name: value.default_properties.platform_name,
            name: value.canonical_name,
            default_deployment_target: value.default_deployment_target,
            default_variant: value.default_variant,
            display_name: value.display_name,
            maximum_deployment_target: value.maximum_deployment_target,
            minimal_display_name: value.minimal_display_name,
            supported_targets: value.supported_targets,
            version: value.version,
        })
    }

    /// Construct an instance by parsing an `SDKSettings.plist` file in a directory.
    ///
    /// Plist files are the legacy mechanism for defining SDK settings. JSON files
    /// are preferred, as they are newer. However, older SDKs lack `SDKSettings.json`
    /// files.
    pub fn from_plist(path: PathBuf, is_symlink: bool, value: plist::Value) -> Result<Self, Error> {
        let value = value.into_dictionary().ok_or(Error::PlistNotDictionary)?;

        let get_string = |dict: &plist::Dictionary, key: &str| -> Result<String, Error> {
            Ok(dict
                .get(key)
                .ok_or_else(|| Error::PlistKeyMissing(key.to_string()))?
                .as_string()
                .ok_or_else(|| Error::PlistKeyNotString(key.to_string()))?
                .to_string())
        };

        let name = get_string(&value, "CanonicalName")?;
        let display_name = get_string(&value, "DisplayName")?;
        let maximum_deployment_target = get_string(&value, "MaximumDeploymentTarget")?;
        let minimal_display_name = get_string(&value, "MinimalDisplayName")?;
        let version = get_string(&value, "Version")?;

        let props = value
            .get("DefaultProperties")
            .ok_or_else(|| Error::PlistKeyMissing("DefaultProperties".to_string()))?
            .as_dictionary()
            .ok_or_else(|| Error::PlistKeyNotDictionary("DefaultProperties".to_string()))?;

        let platform_name = get_string(props, "PLATFORM_NAME")?;
        let default_deployment_target = get_string(
            props,
            &format!("{}_DEPLOYMENT_TARGET", platform_name.to_ascii_uppercase()),
        )?;

        Ok(Self {
            path,
            is_symlink,
            platform_name,
            name,
            default_deployment_target,
            default_variant: None,
            display_name,
            maximum_deployment_target,
            minimal_display_name,
            supported_targets: HashMap::new(),
            version,
        })
    }

    /// Attempt to derive a symver compatible version string for this SDK.
    ///
    /// This essentially pads a `.0` to version strings when there are only
    /// 2 version components, which is common in Apple SDKs. The resulting
    /// version string may conform to Rust's symver format if it was a valid
    /// version string to begin with.
    ///
    /// [None] is returned in cases where the parsed version doesn't look like
    /// a version string.
    pub fn version_symver_compatible(&self) -> Option<String> {
        match self.version.split('.').count() {
            2 => Some(format!("{}.0", self.version)),
            3 => Some(self.version.clone()),
            _ => None,
        }
    }
}

#[cfg(feature = "parse")]
impl TryFrom<UnparsedSdk> for ParsedSdk {
    type Error = Error;

    fn try_from(v: UnparsedSdk) -> Result<Self, Self::Error> {
        Self::from_directory(v.path)
    }
}
