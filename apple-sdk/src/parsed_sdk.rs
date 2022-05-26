//! Data structures in Apple SDKs.

use {
    crate::{ApplePlatform, AppleSdk, Error, SdkPath, SdkVersion, UnparsedSdk},
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

impl AppleSdkSupportedTarget {
    /// Obtain [SdkVersion] for each deployment target this target supports.
    pub fn deployment_targets_versions(&self) -> Vec<SdkVersion> {
        self.valid_deployment_targets
            .iter()
            .map(SdkVersion::from)
            .collect::<Vec<_>>()
    }
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
/// Unlike [UnparsedSdk], this type gives you access to rich metadata about the
/// Apple SDK. This includes things like targeting capabilities.
#[derive(Clone, Debug)]
pub struct ParsedSdk {
    /// Root directory of the SDK.
    path: PathBuf,

    /// Whether the root directory is a symlink to another path.
    is_symlink: bool,

    /// The platform this SDK belongs to.
    platform: ApplePlatform,

    version: SdkVersion,

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
}

impl AsRef<Path> for ParsedSdk {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AppleSdk for ParsedSdk {
    fn from_directory(path: &Path) -> Result<Self, Error> {
        let sdk = SdkPath::from_path(path)?;

        // Need to call symlink_metadata so symlinks aren't followed.
        let metadata = std::fs::symlink_metadata(path)?;

        let is_symlink = metadata.file_type().is_symlink();

        let json_path = path.join("SDKSettings.json");
        let plist_path = path.join("SDKSettings.plist");

        if json_path.exists() {
            let fh = std::fs::File::open(&json_path)?;
            let value: SdkSettingsJson = serde_json::from_reader(fh)?;

            Self::from_json(path.to_path_buf(), is_symlink, sdk.platform, value)
        } else if plist_path.exists() {
            let value = plist::Value::from_file(&plist_path)?;

            Self::from_plist(path.to_path_buf(), is_symlink, sdk.platform, value)
        } else {
            Err(Error::PathNotSdk(path.to_path_buf()))
        }
    }

    fn is_symlink(&self) -> bool {
        self.is_symlink
    }

    fn platform(&self) -> &ApplePlatform {
        &self.platform
    }

    fn version(&self) -> Option<&SdkVersion> {
        Some(&self.version)
    }

    /// Whether this SDK supports the given deployment target.
    ///
    /// This API does not work reliably on SDKs loaded from plists because the plist metadata
    /// lacks the required version constraint annotations.
    fn supports_deployment_target(
        &self,
        target_name: &str,
        target_version: &SdkVersion,
    ) -> Result<bool, Error> {
        Ok(
            if let Some(target) = self.supported_targets.get(target_name) {
                target
                    .deployment_targets_versions()
                    .contains(target_version)
            } else {
                false
            },
        )
    }
}

impl ParsedSdk {
    /// Construct an instance by parsing an `SDKSettings.json` file in a directory.
    ///
    /// These files are only available in more modern SDKs. For macOS, that's 10.14+.
    /// For more reliably SDK construction, use [Self::from_plist()].
    pub fn from_json(
        path: PathBuf,
        is_symlink: bool,
        platform: ApplePlatform,
        value: SdkSettingsJson,
    ) -> Result<Self, Error> {
        Ok(Self {
            path,
            is_symlink,
            platform,
            version: value.version.into(),
            platform_name: value.default_properties.platform_name,
            name: value.canonical_name,
            default_deployment_target: value.default_deployment_target,
            default_variant: value.default_variant,
            display_name: value.display_name,
            maximum_deployment_target: value.maximum_deployment_target,
            minimal_display_name: value.minimal_display_name,
            supported_targets: value.supported_targets,
        })
    }

    /// Construct an instance by parsing an `SDKSettings.plist` file in a directory.
    ///
    /// Plist files are the legacy mechanism for defining SDK settings. JSON files
    /// are preferred, as they are newer. However, older SDKs lack `SDKSettings.json`
    /// files.
    pub fn from_plist(
        path: PathBuf,
        is_symlink: bool,
        platform: ApplePlatform,
        value: plist::Value,
    ) -> Result<Self, Error> {
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

        // The default deployment target can be specified a number of ways.
        //
        // Some SDKs have a property specifying the property defining it. That takes precedence, as
        // explicit > implicit.
        //
        // Otherwise we have to fall back to a heuristic.
        //
        // First we try {platform_name}_DEPLOYMENT_TARGET. Then LLVM target triple + _DEPLOYMENT_TARGET.
        // This heuristic appears to always work.
        let default_deployment_target =
            if let Ok(setting_name) = get_string(props, "DEPLOYMENT_TARGET_SETTING_NAME") {
                get_string(props, &setting_name)?
            } else if let Ok(value) = get_string(
                props,
                &format!("{}_DEPLOYMENT_TARGET", platform_name.to_ascii_uppercase()),
            ) {
                value
            } else {
                let supported_targets = value
                    .get("SupportedTargets")
                    .ok_or_else(|| Error::PlistKeyMissing("SupportedTargets".to_string()))?
                    .as_dictionary()
                    .ok_or_else(|| Error::PlistKeyNotDictionary("SupportedTargets".to_string()))?;

                let default_target = supported_targets
                    .get(&platform_name)
                    .ok_or_else(|| Error::PlistKeyMissing(platform_name.clone()))?
                    .as_dictionary()
                    .ok_or_else(|| Error::PlistKeyNotDictionary(platform_name.clone()))?;

                let llvm_target_triple = get_string(default_target, "LLVMTargetTripleSys")?;

                get_string(
                    props,
                    &format!(
                        "{}_DEPLOYMENT_TARGET",
                        llvm_target_triple.to_ascii_uppercase()
                    ),
                )?
            };

        Ok(Self {
            path,
            is_symlink,
            platform,
            version: version.into(),
            platform_name,
            name,
            default_deployment_target,
            default_variant: None,
            display_name,
            maximum_deployment_target,
            minimal_display_name,
            supported_targets: HashMap::new(),
        })
    }
}

impl TryFrom<UnparsedSdk> for ParsedSdk {
    type Error = Error;

    fn try_from(v: UnparsedSdk) -> Result<Self, Self::Error> {
        Self::from_directory(v.path())
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::{
            DeveloperDirectory, SdkSearch, SdkSearchLocation, COMMAND_LINE_TOOLS_DEFAULT_PATH,
        },
    };

    const MACOSX_10_9_SETTINGS_PLIST: &[u8] = include_bytes!("testfiles/macosx10.9-settings.plist");
    const MACOSX_10_10_SETTINGS_PLIST: &[u8] =
        include_bytes!("testfiles/macosx10.10-settings.plist");
    const MACOSX_10_15_SETTINGS_JSON: &[u8] = include_bytes!("testfiles/macosx10.15-settings.json");
    const MACOSX_11_3_SETTINGS_JSON: &[u8] = include_bytes!("testfiles/macosx11.3-settings.json");

    fn macosx_10_9() -> Result<ParsedSdk, Error> {
        let value = plist::Value::from_reader(std::io::Cursor::new(MACOSX_10_9_SETTINGS_PLIST))?;

        ParsedSdk::from_plist(
            PathBuf::from("MacOSX10.9.sdk"),
            false,
            ApplePlatform::MacOsX,
            value,
        )
    }

    fn macosx_10_10() -> Result<ParsedSdk, Error> {
        let value = plist::Value::from_reader(std::io::Cursor::new(MACOSX_10_10_SETTINGS_PLIST))?;

        ParsedSdk::from_plist(
            PathBuf::from("MacOSX10.10.sdk"),
            false,
            ApplePlatform::MacOsX,
            value,
        )
    }

    fn macosx_10_15() -> Result<ParsedSdk, Error> {
        let value = serde_json::from_slice::<SdkSettingsJson>(MACOSX_10_15_SETTINGS_JSON)?;

        ParsedSdk::from_json(
            PathBuf::from("MacOSX10.15.sdk"),
            false,
            ApplePlatform::MacOsX,
            value,
        )
    }

    fn macosx_11_3() -> Result<ParsedSdk, Error> {
        let value = serde_json::from_slice::<SdkSettingsJson>(MACOSX_11_3_SETTINGS_JSON)?;

        ParsedSdk::from_json(
            PathBuf::from("MacOSX11.3.sdk"),
            false,
            ApplePlatform::MacOsX,
            value,
        )
    }

    fn all_test_sdks() -> Result<Vec<ParsedSdk>, Error> {
        Ok(vec![
            macosx_10_9()?,
            macosx_10_10()?,
            macosx_10_15()?,
            macosx_11_3()?,
        ])
    }

    #[test]
    fn test_find_default_sdks() -> Result<(), Error> {
        if let Ok(developer_dir) = DeveloperDirectory::find_default_required() {
            assert!(!developer_dir.sdks::<ParsedSdk>()?.is_empty());
        }

        Ok(())
    }

    #[test]
    fn test_find_command_line_tools_sdks() -> Result<(), Error> {
        let sdk_path = PathBuf::from(COMMAND_LINE_TOOLS_DEFAULT_PATH).join("SDKs");

        let res = ParsedSdk::find_command_line_tools_sdks()?;

        if sdk_path.exists() {
            assert!(res.is_some());
            assert!(!res.unwrap().is_empty());
        } else {
            assert!(res.is_none());
        }

        Ok(())
    }

    #[test]
    fn find_all_sdks() -> Result<(), Error> {
        for dir in DeveloperDirectory::find_system_xcodes()? {
            for sdk in dir.sdks::<ParsedSdk>()? {
                assert!(!matches!(sdk.platform(), ApplePlatform::Unknown(_)));
                assert!(sdk.version().is_some());
            }
        }

        SdkSearch::default()
            .location(SdkSearchLocation::SystemXcodes)
            .search::<ParsedSdk>()?;

        Ok(())
    }

    #[test]
    fn parse_test_sdks() -> Result<(), Error> {
        all_test_sdks()?;

        Ok(())
    }

    #[test]
    fn supports_deployment_target() -> Result<(), Error> {
        let sdk = macosx_10_15()?;

        assert!(!sdk.supports_deployment_target("ios", &SdkVersion::from("55.0"))?);
        assert!(!sdk.supports_deployment_target("macosx", &SdkVersion::from("10.5"))?);
        assert!(!sdk.supports_deployment_target("macosx", &SdkVersion::from("10.16"))?);
        assert!(!sdk.supports_deployment_target("macosx", &SdkVersion::from("11.0"))?);

        let mut versions = vec!["10.9", "10.10", "10.11", "10.12", "10.13", "10.14", "10.15"];

        for version in &versions {
            assert!(sdk.supports_deployment_target("macosx", &SdkVersion::from(*version))?);
        }

        let sdk = macosx_11_3()?;
        versions.extend(["11.0", "11.1", "11.2", "11.3"]);

        for version in &versions {
            assert!(sdk.supports_deployment_target("macosx", &SdkVersion::from(*version))?);
        }

        // API doesn't work for plists.
        assert!(!macosx_10_9()?.supports_deployment_target("macosx", &SdkVersion::from("10.9"))?);
        assert!(!macosx_10_10()?.supports_deployment_target("macosx", &SdkVersion::from("10.9"))?);

        Ok(())
    }
}
