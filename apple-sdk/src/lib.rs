//! Interact with Apple SDKs.
//!
//! # Important Concepts
//!
//! A *developer directory* is a filesystem tree holding SDKs and tools.
//! If you have Xcode installed, this is likely `/Applications/Xcode.app/Contents/Developer`.
//!
//! A *platform* is a target OS/environment that you build applications for.
//! These typically correspond to `*.platform` directories under `Platforms`
//! subdirectory in the *developer directory. e.g.
//! `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform`.
//!
//! An *SDK* holds header files, library stubs, and other files enabling you
//! to compile applications targeting a *platform* for a supported version range.
//! SDKs usually exist in an `SDKs` directory under a *platform* directory. e.g.
//! `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/SDKs/MacOSX12.3.sdk`
//! or `/Library/Developer/CommandLineTools/SDKs/MacOSX12.3.sdk`.
//!
//! # Apple SDKs
//!
//! We model Apple SDKs using the [AppleSdkDirectory] and [AppleSdk] types. The
//! latter requires the `parse` crate feature in order to activate support for
//! parsing JSON and plist files.

#[cfg(feature = "parse")]
mod data;

use std::{
    fmt::{Display, Formatter},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

#[cfg(feature = "parse")]
use std::collections::HashMap;

#[cfg(feature = "parse")]
pub use crate::data::{AppleSdkSupportedTarget, SdkSettingsJson, SdkSettingsJsonDefaultProperties};

/// Default install path for the Xcode command line tools.
pub const COMMAND_LINE_TOOLS_DEFAULT_PATH: &str = "/Library/Developer/CommandLineTools";

/// Default path to Xcode application.
pub const XCODE_APP_DEFAULT_PATH: &str = "/Applications/Xcode.app";

/// Relative path under Xcode.app directories defining a `Developer` directory.
///
/// This directory contains platforms, toolchains, etc.
pub const XCODE_APP_RELATIVE_PATH_DEVELOPER: &str = "Contents/Developer";

/// Error type for this crate.
#[derive(Debug)]
pub enum Error {
    /// Error occurred when running `xcode-select`.
    XcodeSelectRun(std::io::Error),
    /// `xcode-select` did not run successfully.
    XcodeSelectBadStatus(ExitStatus),
    /// Generic I/O error.
    Io(std::io::Error),
    /// A path is not an Apple SDK.
    PathNotSdk(PathBuf),
    /// A plist value is not a dictionary.
    PlistNotDictionary,
    /// An expected plist key is missing.
    ///
    /// If you see this, it might represent a logic error in this crate.
    PlistKeyMissing(String),
    /// A plist key's value is not a dictionary.
    ///
    /// If you see this, it might represent a logic error in this crate.
    PlistKeyNotDictionary(String),
    /// A plist key's value is not a string.
    ///
    /// If you see this, it might represent a logic error in this crate.
    PlistKeyNotString(String),
    #[cfg(feature = "parse")]
    SerdeJson(serde_json::Error),
    #[cfg(feature = "plist")]
    Plist(plist::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::XcodeSelectRun(err) => {
                f.write_fmt(format_args!("Error running xcode-select: {}", err))
            }
            Self::XcodeSelectBadStatus(v) => {
                f.write_fmt(format_args!("Error running xcode-select: {}", v))
            }
            Self::Io(err) => f.write_fmt(format_args!("I/O error: {}", err)),
            Self::PathNotSdk(p) => {
                f.write_fmt(format_args!("path is not an Apple SDK: {}", p.display()))
            }
            Self::PlistNotDictionary => f.write_str("plist value not a dictionary"),
            Self::PlistKeyMissing(key) => f.write_fmt(format_args!("plist key missing: {}", key)),
            Self::PlistKeyNotDictionary(key) => {
                f.write_fmt(format_args!("plist key not a dictionary: {}", key))
            }
            Self::PlistKeyNotString(key) => {
                f.write_fmt(format_args!("plist key not a string: {}", key))
            }
            #[cfg(feature = "parse")]
            Self::SerdeJson(err) => f.write_fmt(format_args!("JSON parsing error: {}", err)),
            #[cfg(feature = "plist")]
            Self::Plist(err) => f.write_fmt(format_args!("plist error: {}", err)),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(feature = "parse")]
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJson(e)
    }
}

#[cfg(feature = "parse")]
impl From<plist::Error> for Error {
    fn from(e: plist::Error) -> Self {
        Self::Plist(e)
    }
}

/// Obtain the current developer directory where SDKs and tools are installed.
///
/// This returns the `DEVELOPER_DIR` environment variable if found or
/// uses the `xcode-select` logic for locating the developer directory if not.
/// Failure the locate a directory results in `Err`.
///
/// The returned path is not verified to exist.
pub fn default_developer_directory() -> Result<PathBuf, Error> {
    // DEVELOPER_DIR environment variable overrides any settings.
    if let Ok(env) = std::env::var("DEVELOPER_DIR") {
        Ok(PathBuf::from(env))
    } else {
        // We use xcode-select to find the directory. But this probably
        // just reads from a plist or something. We could potentially
        // reimplement this logic in pure Rust...
        let output = Command::new("xcode-select")
            .args(&["--print-path"])
            .stderr(Stdio::null())
            .output()
            .map_err(Error::XcodeSelectRun)?;

        if output.status.success() {
            // We should arguably use OsString here. Keep it simple until someone
            // complains.
            let path = String::from_utf8_lossy(&output.stdout);

            Ok(PathBuf::from(path.trim()))
        } else {
            Err(Error::XcodeSelectBadStatus(output.status))
        }
    }
}

/// Obtain the path to the `Developer` directory in the default Xcode app.
///
/// Returns `Some` if Xcode is installed in its default location and has
/// a `Developer` directory or `None` if not.
pub fn default_xcode_developer_directory() -> Option<PathBuf> {
    let path = PathBuf::from(XCODE_APP_DEFAULT_PATH).join(XCODE_APP_RELATIVE_PATH_DEVELOPER);

    if path.exists() {
        Some(path)
    } else {
        None
    }
}

/// Attempt to resolve all available Xcode applications in an `Applications` directory.
///
/// This function is a convenience method for iterating a directory
/// and filtering for `Xcode*.app` entries.
///
/// No guarantee is made about whether the directory constitutes a working
/// Xcode application.
pub fn find_xcode_apps(applications_dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let dir = match std::fs::read_dir(&applications_dir) {
        Ok(v) => Ok(v),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(vec![]);
            } else {
                Err(Error::from(e))
            }
        }
    }?;

    let mut res = dir
        .into_iter()
        .map(|entry| {
            let entry = entry?;

            let name = entry.file_name();
            let file_name = name.to_string_lossy();

            if file_name.starts_with("Xcode") && file_name.ends_with(".app") {
                Ok(Some(entry.path()))
            } else {
                Ok(None)
            }
        })
        .collect::<Result<Vec<_>, Error>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    // Make deterministic.
    res.sort();

    Ok(res)
}

/// Find all system installed Xcode applications.
///
/// This is a convenience method for [find_xcode_apps()] looking under `/Applications`.
/// This location is typically where Xcode is installed.
pub fn find_system_xcode_applications() -> Result<Vec<PathBuf>, Error> {
    find_xcode_apps(&PathBuf::from("/Applications"))
}

/// Finds all `Developer` directories for installed Xcode applications for system application installs.
///
/// This is a convenience method for [find_system_xcode_applications()] plus
/// resolving the `Developer` directory and filtering on missing items.
///
/// It will return all available `Developer` directories for all Xcode installs
/// under `/Applications`.
pub fn find_system_xcode_developer_directories() -> Result<Vec<PathBuf>, Error> {
    Ok(find_system_xcode_applications()?
        .into_iter()
        .filter_map(|p| {
            let developer_path = p.join(XCODE_APP_RELATIVE_PATH_DEVELOPER);

            if developer_path.exists() {
                Some(developer_path)
            } else {
                None
            }
        })
        .collect::<Vec<_>>())
}

/// Attempt to derive the name of a platform from a directory path.
///
/// Returns `Some(platform)` if the directory represents a platform or
/// `None` otherwise.
fn platform_from_path(path: &Path) -> Option<String> {
    if let Some(file_name) = path.file_name() {
        if let Some(name) = file_name.to_str() {
            let parts = name.splitn(2, '.').collect::<Vec<_>>();

            if parts.len() == 2 && parts[1] == "platform" {
                return Some(parts[0].to_string());
            }
        }
    }

    None
}

/// Find "platforms" given a developer directory.
///
/// Platforms are effectively targets that can be built for.
///
/// Platforms are defined by the presence of a `Platforms` directory under
/// the developer directory. This directory layout is only recognized
/// for modern Xcode layouts.
///
/// Returns a vector of (platform, path) tuples denoting the platform
/// name and its base directory.
pub fn find_developer_platforms(developer_dir: &Path) -> Result<Vec<(String, PathBuf)>, Error> {
    let platforms_path = developer_dir.join("Platforms");

    let dir = match std::fs::read_dir(&platforms_path) {
        Ok(v) => Ok(v),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(vec![]);
            } else {
                Err(Error::from(e))
            }
        }
    }?;

    let mut res = vec![];

    for entry in dir {
        let entry = entry?;

        if let Some(platform) = platform_from_path(&entry.path()) {
            res.push((platform, entry.path()));
        }
    }

    Ok(res)
}

/// A directory purported to hold an Apple SDK.
#[derive(Clone, Debug)]
pub struct AppleSdkDirectory {
    /// Root directory of the SDK.
    pub path: PathBuf,

    /// Whether the root directory is a symlink to another path.
    pub is_symlink: bool,
}

impl AppleSdkDirectory {
    /// Attempt to resolve an SDK from a path to the SDK root directory.
    pub fn from_directory(path: &Path) -> Result<Self, Error> {
        // Need to call symlink_metadata so symlinks aren't followed.
        let metadata = std::fs::symlink_metadata(path)?;

        let is_symlink = metadata.file_type().is_symlink();

        let json_path = path.join("SDKSettings.json");
        let plist_path = path.join("SDKSettings.plist");

        if json_path.exists() || plist_path.exists() {
            Ok(Self {
                path: path.to_path_buf(),
                is_symlink,
            })
        } else {
            Err(Error::PathNotSdk(path.to_path_buf()))
        }
    }

    #[cfg(feature = "parse")]
    /// Attempt to convert into an [AppleSdk] by parsing an `SDKSettings.*` file.
    pub fn try_parse(self) -> Result<AppleSdk, Error> {
        self.try_into()
    }
}

/// An Apple SDK with parsed settings.
///
/// Unlike [AppleSdkDirectory], this type gives you access to rich metadata about the
/// Apple SDK. This includes things like targeting capabilities.
#[cfg(feature = "parse")]
#[derive(Clone, Debug)]
pub struct AppleSdk {
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
impl AppleSdk {
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
impl TryFrom<AppleSdkDirectory> for AppleSdk {
    type Error = Error;

    fn try_from(v: AppleSdkDirectory) -> Result<Self, Self::Error> {
        Self::from_directory(v.path)
    }
}

/// Finds SDKs in a specified directory.
///
/// Directory entries are often symlinks pointing to other directories.
/// SDKs are annotated with an `is_symlink` field to denote when this is
/// the case. Callers may want to filter out symlinked SDKs to avoid
/// duplicates.
pub fn find_sdks_in_directory(root: &Path) -> Result<Vec<AppleSdkDirectory>, Error> {
    let dir = match std::fs::read_dir(&root) {
        Ok(v) => Ok(v),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(vec![]);
            } else {
                Err(Error::from(e))
            }
        }
    }?;

    let mut res = vec![];

    for entry in dir {
        let entry = entry?;

        match AppleSdkDirectory::from_directory(&entry.path()) {
            Ok(sdk) => {
                res.push(sdk);
            }
            Err(Error::PathNotSdk(_)) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(res)
}

/// Finds SDKs in a platform directory.
///
/// This function is a simple wrapper around [find_sdks_in_directory()]
/// looking under the `Developer/SDKs` directory, which is the path under
/// platform directories containing SDKs.
///
/// A common input path is `/Applications/Xcode.app/Contents/Developer/Platforms/*.platform`.
pub fn find_sdks_in_platform(platform_dir: &Path) -> Result<Vec<AppleSdkDirectory>, Error> {
    let sdks_path = platform_dir.join("Developer").join("SDKs");

    find_sdks_in_directory(&sdks_path)
}

/// Locate SDKs given the path to a developer directory.
///
/// This is effectively a convenience method for calling
/// [find_developer_platforms()] + [find_sdks_in_platform()] and chaining the
/// results.
///
/// A common input path is `/Applications/Xcode.app/Contents/Developer` or the
/// return value of [default_developer_directory()].
pub fn find_developer_sdks(developer_dir: &Path) -> Result<Vec<AppleSdkDirectory>, Error> {
    Ok(find_developer_platforms(developer_dir)?
        .into_iter()
        .map(|(_, platform_path)| Ok(find_sdks_in_platform(&platform_path)?.into_iter()))
        .collect::<Result<Vec<_>, Error>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>())
}

/// Discover SDKs in the default developer directory.
///
/// This is a convenience function for calling [find_developer_sdks()] with the output
/// of [default_developer_directory()].
pub fn find_default_developer_sdks() -> Result<Vec<AppleSdkDirectory>, Error> {
    let developer_dir = default_developer_directory()?;

    find_developer_sdks(&developer_dir)
}

/// Locate SDKs installed as part of the Xcode Command Line Tools.
///
/// This is a convenience method for looking for SDKs in the `SDKs` directory
/// under the default install path for the Xcode Command Line Tools.
///
/// Returns `Ok(None)` if the Xcode Command Line Tools are not present in
/// this directory or doesn't have an `SDKs` directory.
pub fn find_command_line_tools_sdks() -> Result<Option<Vec<AppleSdkDirectory>>, Error> {
    let sdk_path = PathBuf::from(COMMAND_LINE_TOOLS_DEFAULT_PATH).join("SDKs");

    if sdk_path.exists() {
        Ok(Some(find_sdks_in_directory(&sdk_path)?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_find_system_xcode_applications() -> Result<(), Error> {
        let res = find_system_xcode_applications()?;

        if PathBuf::from(XCODE_APP_DEFAULT_PATH).exists() {
            assert!(!res.is_empty());
        }

        Ok(())
    }

    #[test]
    fn test_find_system_xcode_developer_directories() -> Result<(), Error> {
        let res = find_system_xcode_developer_directories()?;

        if PathBuf::from(XCODE_APP_DEFAULT_PATH).exists() {
            assert!(!res.is_empty());
        }

        Ok(())
    }

    /// Verifies various discovery operations on a macOS GitHub Actions runner.
    ///
    /// This assumes we're using GitHub's official macOS runners.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_github_actions() -> Result<(), Error> {
        if std::env::var("GITHUB_ACTIONS").is_err() {
            return Ok(());
        }

        assert_eq!(
            default_xcode_developer_directory(),
            Some(PathBuf::from("/Applications/Xcode.app/Contents/Developer"))
        );
        assert!(PathBuf::from(COMMAND_LINE_TOOLS_DEFAULT_PATH).exists());

        // GitHub Actions runners have multiple Xcode applications installed.
        assert!(find_system_xcode_applications()?.len() > 5);

        // We should be able to resolve developer directories for all system Xcode
        // applications.
        assert_eq!(
            find_system_xcode_applications()?.len(),
            find_system_xcode_developer_directories()?.len()
        );

        // We should be able to resolve SDKs for all system Xcode applications.
        for path in find_system_xcode_developer_directories()? {
            find_developer_sdks(&path)?;
        }

        Ok(())
    }

    #[test]
    fn test_find_default_sdks() -> Result<(), Error> {
        if let Ok(developer_dir) = default_developer_directory() {
            assert!(!find_developer_sdks(&developer_dir)?.is_empty());
            assert!(!find_default_developer_sdks()?.is_empty());
        }

        Ok(())
    }

    #[test]
    fn test_find_command_line_tools_sdks() -> Result<(), Error> {
        let sdk_path = PathBuf::from(COMMAND_LINE_TOOLS_DEFAULT_PATH).join("SDKs");

        let res = find_command_line_tools_sdks()?;

        if sdk_path.exists() {
            assert!(res.is_some());
            assert!(!res.unwrap().is_empty());
        } else {
            assert!(res.is_none());
        }

        Ok(())
    }
}
