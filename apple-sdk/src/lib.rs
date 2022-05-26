//! Interact with Apple SDKs.
//!
//! # Important Concepts
//!
//! A *developer directory* is a filesystem tree holding SDKs and tools.
//! If you have Xcode installed, this is likely `/Applications/Xcode.app/Contents/Developer`.
//!
//! A *platform* is a target OS/environment that you build applications for.
//! These typically correspond to `*.platform` directories under `Platforms`
//! subdirectory in the *developer directory*. e.g.
//! `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform`.
//!
//! An *SDK* holds header files, library stubs, and other files enabling you
//! to compile applications targeting a *platform* for a supported version range.
//! SDKs usually exist in an `SDKs` directory under a *platform* directory. e.g.
//! `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/SDKs/MacOSX12.3.sdk`
//! or `/Library/Developer/CommandLineTools/SDKs/MacOSX12.3.sdk`.
//!
//! # Developer Directories
//!
//! Developer Directories are modeled via the [DeveloperDirectory] struct. This
//! type contains functions for locating developer directories and resolving the
//! default developer directory to use.
//!
//! # Apple Platforms
//!
//! We model an abstract Apple platform via the [Platform] enum.
//!
//! A directory containing an Apple platform is represented by the
//! [PlatformDirectory] struct.
//!
//! # Apple SDKs
//!
//! We model Apple SDKs using the [SimpleSdk] and [ParsedSdk] types. The
//! latter requires the `parse` crate feature in order to activate support for
//! parsing JSON and plist files.
//!
//! Both these types are essentially a reference to a directory. [SimpleSdk]
//! is little more than a reference to a filesystem path. However, [ParsedSdk]
//! parses the `SDKSettings.json` or `SDKSettings.plist` file within the SDK
//! and is able to obtain rich metadata about the SDK, such as the names of
//! machine architectures it can target, which OS versions it supports targeting,
//! and more.
//!
//! Both these types implement the [AppleSdk] trait, which you'll likely want
//! to import in order to use its APIs for searching for and constructing SDKs.
//!
//! # SDK Searching
//!
//! This crate supports searching for an appropriate SDK to use given search
//! parameters and requirements. This functionality can be used to locate the
//! most appropriate SDK from many available on the current system.
//!
//! This functionality is exposed through the [SdkSearch] struct. See its
//! documentation for more.
//!
//! # Common Functionality
//!
//! To locate the default SDK to use, do something like this:
//!
//! ```
//! use apple_sdk::{SdkSearch, Platform, SimpleSdk, SdkSorting, AppleSdk};
//!
//! // This search will honor the `SDKROOT` and `DEVELOPER_DIR` environment variables.
//! let sdks = SdkSearch::default()
//!     .platform(Platform::MacOsX)
//!     // Ideally we'd call e.g. `.deployment_target("macosx", "11.0")` to require
//!     // the SDK to support a specific deployment target. This requires the
//!     // `ParsedSdk` type, which requires the `parse` crate feature.
//!     .sorting(SdkSorting::VersionDescending)
//!     .search::<SimpleSdk>()
//!     .expect("failed to search for SDKs");
//!
//! if let Some(sdk) = sdks.first() {
//!     println!("{}", sdk.as_sdk_path());
//! }
//! ```

#[cfg(feature = "parse")]
mod parsed_sdk;
mod search;
mod simple_sdk;

use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
    ops::Deref,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    str::FromStr,
};

pub use crate::{search::*, simple_sdk::SimpleSdk};

#[cfg(feature = "parse")]
pub use crate::parsed_sdk::{
    ParsedSdk, SdkSettingsJson, SdkSettingsJsonDefaultProperties, SupportedTarget,
};

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
    /// A developer directory could not be found.
    DeveloperDirectoryNotFound,
    /// A path is not a Developer Directory.
    PathNotDeveloper(PathBuf),
    /// A path is not an Apple Platform directory.
    PathNotPlatform(PathBuf),
    /// A path is not an Apple SDK.
    PathNotSdk(PathBuf),
    /// A version string could not be parsed.
    VersionParse(String),
    /// Certain functionality is not supported.
    FunctionalityNotSupported(&'static str),
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
            Self::DeveloperDirectoryNotFound => f.write_str("could not find a Developer Directory"),
            Self::PathNotDeveloper(p) => f.write_fmt(format_args!(
                "path is not a Developer directory: {}",
                p.display()
            )),
            Self::PathNotPlatform(p) => f.write_fmt(format_args!(
                "path is not an Apple Platform: {}",
                p.display()
            )),
            Self::PathNotSdk(p) => {
                f.write_fmt(format_args!("path is not an Apple SDK: {}", p.display()))
            }
            Self::VersionParse(s) => f.write_fmt(format_args!("malformed version string: {}", s)),
            Self::FunctionalityNotSupported(s) => f.write_fmt(format_args!("not supported: {}", s)),
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

/// A known Apple platform type.
///
/// Instances are equivalent to each other if their filesystem representation
/// is equivalent. This ensures that [Self::Unknown] will equate to a variant of
/// its string value matches a known type.
#[derive(Clone, Debug)]
pub enum Platform {
    AppleTvOs,
    AppleTvSimulator,
    DriverKit,
    IPhoneOs,
    IPhoneSimulator,
    MacOsX,
    WatchOs,
    WatchSimulator,
    Unknown(String),
}

impl FromStr for Platform {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We do a case insensitive comparison so we're lenient in parsing input.
        match s.to_ascii_lowercase().as_str() {
            "appletvos" => Ok(Self::AppleTvOs),
            "appletvsimulator" => Ok(Self::AppleTvSimulator),
            "driverkit" => Ok(Self::DriverKit),
            "iphoneos" => Ok(Self::IPhoneOs),
            "iphonesimulator" => Ok(Self::IPhoneSimulator),
            "macosx" => Ok(Self::MacOsX),
            "watchos" => Ok(Self::WatchOs),
            "watchsimulator" => Ok(Self::WatchSimulator),
            v => Ok(Self::Unknown(v.to_string())),
        }
    }
}

impl PartialEq for Platform {
    fn eq(&self, other: &Self) -> bool {
        self.filesystem_name().eq(other.filesystem_name())
    }
}

impl Eq for Platform {}

impl TryFrom<&str> for Platform {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl Platform {
    /// Attempt to construct an instance from a filesystem path to a platform directory.
    ///
    /// The argument should be the path of a `*.platform` directory. e.g.
    /// `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform`.
    ///
    /// Will return [Error::PathNotPlatform] if this does not appear to be a known
    /// platform path.
    pub fn from_platform_path(p: &Path) -> Result<Self, Error> {
        let (name, platform) = p
            .file_name()
            .ok_or_else(|| Error::PathNotPlatform(p.to_path_buf()))?
            .to_str()
            .ok_or_else(|| Error::PathNotPlatform(p.to_path_buf()))?
            .split_once('.')
            .ok_or_else(|| Error::PathNotPlatform(p.to_path_buf()))?;

        if platform == "platform" {
            Self::from_str(name)
        } else {
            Err(Error::PathNotPlatform(p.to_path_buf()))
        }
    }

    /// Obtain the name of this platform as used in filesystem paths.
    ///
    /// This is just the platform part of the name without the trailing
    /// `.platform`. This string appears in the `*.platform` directory names
    /// as well as in SDK directory names preceding the trailing `.sdk` and
    /// optional SDK version.
    pub fn filesystem_name(&self) -> &str {
        match self {
            Self::AppleTvOs => "AppleTVOS",
            Self::AppleTvSimulator => "AppleTVSimulator",
            Self::DriverKit => "DriverKit",
            Self::IPhoneOs => "iPhoneOS",
            Self::IPhoneSimulator => "iPhoneSimulator",
            Self::MacOsX => "MacOSX",
            Self::WatchOs => "WatchOS",
            Self::WatchSimulator => "WatchSimulator",
            Self::Unknown(v) => v,
        }
    }

    /// Obtain the directory name of this platform.
    ///
    /// This simply appends `.platform` to [Self::filesystem_name()].
    pub fn directory_name(&self) -> String {
        format!("{}.platform", self.filesystem_name())
    }

    /// Obtain the path of this platform relative to a developer directory root.
    pub fn path_in_developer_directory(&self, developer_directory: impl AsRef<Path>) -> PathBuf {
        developer_directory
            .as_ref()
            .join("Platforms")
            .join(self.directory_name())
    }
}

/// Represents an Apple Platform directory.
///
/// This is just a thin abstraction over a filesystem path and a [Platform] instance.
///
/// Equivalence and sorting are implemented in terms of the path component
/// only. The assumption here is the [Platform] is fully derived from the filesystem
/// path and this derivation is deterministic.
pub struct PlatformDirectory {
    /// The filesystem path to this directory.
    path: PathBuf,

    /// The platform within this directory.
    platform: Platform,
}

impl PlatformDirectory {
    /// Attempt to construct an instance from a filesystem path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let platform = Platform::from_platform_path(&path)?;

        Ok(Self { path, platform })
    }

    /// The filesystem path of this instance.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The filesystem path to the directory holding SDKs.
    ///
    /// The returned path is not validated to exist.
    pub fn sdks_path(&self) -> PathBuf {
        self.path.join("Developer").join("SDKs")
    }

    /// Finds SDKs in this platform directory.
    ///
    /// The type of SDK to resolve must be specified by the caller.
    ///
    /// This function is a simple wrapper around [AppleSdk::find_in_directory()] looking
    /// under the `Developer/SDKs` directory, which is where SDKs are located in platform
    /// directories.
    pub fn find_sdks<T: AppleSdk>(&self) -> Result<Vec<T>, Error> {
        T::find_in_directory(&self.sdks_path())
    }
}

impl AsRef<Path> for PlatformDirectory {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Platform> for PlatformDirectory {
    fn as_ref(&self) -> &Platform {
        &self.platform
    }
}

impl Deref for PlatformDirectory {
    type Target = Platform;

    fn deref(&self) -> &Self::Target {
        &self.platform
    }
}

impl PartialEq for PlatformDirectory {
    fn eq(&self, other: &Self) -> bool {
        self.path.eq(&other.path)
    }
}

impl Eq for PlatformDirectory {}

impl PartialOrd for PlatformDirectory {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.path.partial_cmp(&other.path)
    }
}

impl Ord for PlatformDirectory {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
    }
}

/// A directory containing Apple platforms, SDKs, and other tools.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeveloperDirectory {
    path: PathBuf,
}

impl AsRef<Path> for DeveloperDirectory {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl From<&Path> for DeveloperDirectory {
    fn from(p: &Path) -> Self {
        Self {
            path: p.to_path_buf(),
        }
    }
}

impl From<PathBuf> for DeveloperDirectory {
    fn from(path: PathBuf) -> Self {
        Self { path }
    }
}

impl From<&PathBuf> for DeveloperDirectory {
    fn from(path: &PathBuf) -> Self {
        Self { path: path.clone() }
    }
}

impl DeveloperDirectory {
    /// Resolve an instance from the `DEVELOPER_DIR` environment variable.
    ///
    /// This environment variable is used by convention to override default search
    /// locations for the developer directory.
    ///
    /// If `DEVELOPER_DIR` is defined, the value/path is validated for existence
    /// and an error is returned if it doesn't exist.
    ///
    /// If `DEVELOPER_DIR` isn't defined, returns `Ok(None)`.
    pub fn from_env() -> Result<Option<Self>, Error> {
        if let Some(value) = std::env::var_os("DEVELOPER_DIR") {
            let path = PathBuf::from(value);

            if path.exists() {
                Ok(Some(Self { path }))
            } else {
                Err(Error::PathNotDeveloper(path))
            }
        } else {
            Ok(None)
        }
    }

    /// Attempt to resolve an instance by running `xcode-select`.
    ///
    /// The output from `xcode-select` is implicitly trusted and no validation
    /// of the path is performed.
    pub fn from_xcode_select() -> Result<Self, Error> {
        let output = Command::new("xcode-select")
            .args(&["--print-path"])
            .stderr(Stdio::null())
            .output()
            .map_err(Error::XcodeSelectRun)?;

        if output.status.success() {
            // We should arguably use OsString here. Keep it simple until someone
            // complains.
            let path = String::from_utf8_lossy(&output.stdout);
            let path = PathBuf::from(path.trim());

            Ok(Self { path })
        } else {
            Err(Error::XcodeSelectBadStatus(output.status))
        }
    }

    /// Attempt to resolve an instance from the default Xcode.app location.
    ///
    /// This looks for a system installed `Xcode.app` and for the developer
    /// directory within. If found, returns `Some`. If not, returns `None`.
    pub fn default_xcode() -> Option<Self> {
        let path = PathBuf::from(XCODE_APP_DEFAULT_PATH).join(XCODE_APP_RELATIVE_PATH_DEVELOPER);

        if path.exists() {
            Some(Self { path })
        } else {
            None
        }
    }

    /// Finds all `Developer` directories for system installed Xcode applications.
    ///
    /// This is a convenience method for [find_system_xcode_applications()] plus
    /// resolving the `Developer` directory and filtering on missing items.
    ///
    /// It will return all available `Developer` directories for all Xcode installs
    /// under `/Applications`.
    pub fn find_system_xcodes() -> Result<Vec<Self>, Error> {
        Ok(find_system_xcode_applications()?
            .into_iter()
            .filter_map(|p| {
                let path = p.join(XCODE_APP_RELATIVE_PATH_DEVELOPER);

                if path.exists() {
                    Some(Self { path })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>())
    }

    /// Attempt to find a Developer Directory using reasonable semantics.
    ///
    /// This is probably what most end-users want to use for resolving the path to a
    /// Developer Directory.
    ///
    /// This is a convenience function for calling other APIs on this type to resolve
    /// the default instance.
    ///
    /// In priority order:
    ///
    /// 1. `DEVELOPER_DIR`
    /// 2. System Xcode.app application.
    /// 3. `xcode-select` output.
    ///
    /// Errors only if `DEVELOPER_DIR` is defined and it points to an invalid path.
    /// Errors from running `xcode-select` are ignored.
    pub fn find_default() -> Result<Option<Self>, Error> {
        if let Some(v) = Self::from_env()? {
            Ok(Some(v))
        } else if let Some(v) = Self::default_xcode() {
            Ok(Some(v))
        } else if let Ok(v) = Self::from_xcode_select() {
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    /// Find the Developer Directory and error if not found.
    ///
    /// This is a wrapper around [Self::find_default()] that will error if no Developer Directory
    /// could be found.
    pub fn find_default_required() -> Result<Self, Error> {
        if let Some(v) = Self::find_default()? {
            Ok(v)
        } else {
            Err(Error::DeveloperDirectoryNotFound)
        }
    }

    /// The filesystem path to this developer directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path to the directory containing platforms.
    pub fn platforms_path(&self) -> PathBuf {
        self.path.join("Platforms")
    }

    /// Find platform directories within this developer directory.
    ///
    /// Platforms are defined by the presence of a `Platforms` directory under
    /// the developer directory. This directory layout is only recognized
    /// for modern Xcode layouts.
    ///
    /// Returns all discovered instances inside this developer directory.
    ///
    /// The return order is sorted and deterministic.
    pub fn platforms(&self) -> Result<Vec<PlatformDirectory>, Error> {
        let platforms_path = self.platforms_path();

        let dir = match std::fs::read_dir(platforms_path) {
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

            if let Ok(platform) = PlatformDirectory::from_path(entry.path()) {
                res.push(platform);
            }
        }

        // Make deterministic.
        res.sort();

        Ok(res)
    }

    /// Find SDKs within this developer directory.
    ///
    /// This is a convenience method for calling [Self::platforms()] +
    /// [PlatformDirectory::find_sdks()] and chaining the results.
    pub fn sdks<SDK: AppleSdk>(&self) -> Result<Vec<SDK>, Error> {
        Ok(self
            .platforms()?
            .into_iter()
            .map(|platform| Ok(platform.find_sdks()?.into_iter()))
            .collect::<Result<Vec<_>, Error>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>())
    }
}

/// Obtain the path to SDKs within an Xcode Command Line Tools installation.
///
/// Returns [Some] if we found a path in the expected location or [None] otherwise.
pub fn command_line_tools_sdks_directory() -> Option<PathBuf> {
    let sdk_path = PathBuf::from(COMMAND_LINE_TOOLS_DEFAULT_PATH).join("SDKs");

    if sdk_path.exists() {
        Some(sdk_path)
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
///
/// The results are sorted according to the directory name. However, `Xcode.app` always
/// sorts first so the default application name is always preferred.
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
    res.sort_by(|a, b| match (a.file_name(), b.file_name()) {
        (Some(x), _) if x == "Xcode.app" => Ordering::Less,
        (_, Some(x)) if x == "Xcode.app" => Ordering::Greater,
        (_, _) => a.cmp(b),
    });

    Ok(res)
}

/// Find all system installed Xcode applications.
///
/// This is a convenience method for [find_xcode_apps()] looking under `/Applications`.
/// This location is typically where Xcode is installed.
pub fn find_system_xcode_applications() -> Result<Vec<PathBuf>, Error> {
    find_xcode_apps(&PathBuf::from("/Applications"))
}

/// Represents an SDK version string.
///
/// This type attempts to apply semantic versioning onto SDK version strings
/// without pulling in additional crates.
///
/// The version string is not validated for correctness at construction time:
/// any string can be stored.
///
/// The string is interpreted as a `X.Y` or `X.Y.Z` semantic version string
/// where each component is an integer.
///
/// For ordering, an invalid string is interpreted as the version `0.0.0` and
/// therefore should always sort less than a well-formed version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkVersion {
    value: String,
}

impl Display for SdkVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl AsRef<str> for SdkVersion {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl From<String> for SdkVersion {
    fn from(value: String) -> Self {
        Self { value }
    }
}

impl From<&str> for SdkVersion {
    fn from(s: &str) -> Self {
        Self::from(s.to_string())
    }
}

impl From<&String> for SdkVersion {
    fn from(s: &String) -> Self {
        Self::from(s.to_string())
    }
}

impl SdkVersion {
    fn normalized_version(&self) -> Result<(u8, u8, u8), Error> {
        let ints = self
            .value
            .split('.')
            .map(|x| u8::from_str(x).map_err(|_| Error::VersionParse(self.value.to_string())))
            .collect::<Result<Vec<_>, Error>>()?;

        match ints.len() {
            1 => Ok((ints[0], 0, 0)),
            2 => Ok((ints[0], ints[1], 0)),
            3 => Ok((ints[0], ints[1], ints[2])),
            _ => Err(Error::VersionParse(self.value.to_string())),
        }
    }

    /// Resolve a version string that adheres to Rust's semantic version string format.
    ///
    /// The returned string will have the form `X.Y.Z` where all components are
    /// integers.
    pub fn semantic_version(&self) -> Result<String, Error> {
        let (x, y, z) = self.normalized_version()?;

        Ok(format!("{}.{}.{}", x, y, z))
    }
}

impl PartialOrd for SdkVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = self.normalized_version().unwrap_or((0, 0, 0));
        let b = other.normalized_version().unwrap_or((0, 0, 0));

        a.partial_cmp(&b)
    }
}

impl Ord for SdkVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

/// Represents an SDK path with metadata parsed from the path.
#[derive(Clone, Debug)]
pub struct SdkPath {
    /// The filesystem path.
    pub path: PathBuf,

    /// The platform this SDK belongs to.
    pub platform: Platform,

    /// The version of the SDK.
    ///
    /// Only present if the version occurred in the directory name. Use
    /// [AppleSdk] to parse SDK directories to reliably obtain the SDK version.
    pub version: Option<SdkVersion>,
}

impl Display for SdkPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{} (version: {}) SDK at {}",
            self.platform.filesystem_name(),
            if let Some(version) = &self.version {
                version.value.as_str()
            } else {
                "unknown"
            },
            self.path.display()
        ))
    }
}

impl SdkPath {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();

        let s = path
            .file_name()
            .ok_or_else(|| Error::PathNotSdk(path.clone()))?
            .to_str()
            .ok_or_else(|| Error::PathNotSdk(path.clone()))?;

        let (prefix, sdk) = s
            .rsplit_once('.')
            .ok_or_else(|| Error::PathNotSdk(path.clone()))?;

        if sdk != "sdk" {
            return Err(Error::PathNotSdk(path));
        }

        // prefix can be a platform name (e.g. `MacOSX`) or a platform name + version
        // (e.g. `MacOSX12.4`).
        let (platform_name, version) = if let Some(first_digit) = prefix
            .chars()
            .enumerate()
            .find_map(|(i, c)| if c.is_numeric() { Some(i) } else { None })
        {
            let (name, version) = prefix.split_at(first_digit);

            (name, Some(version.to_string().into()))
        } else {
            (prefix, None)
        };

        let platform = Platform::from_str(platform_name)?;

        Ok(Self {
            path,
            platform,
            version,
        })
    }
}

/// Defines common behavior for types representing Apple SDKs.
pub trait AppleSdk: Sized + AsRef<Path> {
    /// Attempt to construct an instance from a filesystem directory.
    ///
    /// Implementations will likely error with [Error::PathNotSdk] or
    /// [Error::Io] if the input path is not an Apple SDK.
    fn from_directory(path: &Path) -> Result<Self, Error>;

    /// Find Apple SDKs in a specified directory.
    ///
    /// Directory entries are often symlinks pointing to other directories.
    /// SDKs are annotated with an `is_symlink` field to denote when this is
    /// the case. Callers may want to filter out symlinked SDKs to avoid
    /// duplicates.
    fn find_in_directory(root: &Path) -> Result<Vec<Self>, Error> {
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

            match Self::from_directory(&entry.path()) {
                Ok(sdk) => {
                    res.push(sdk);
                }
                Err(Error::PathNotSdk(_)) => {}
                Err(err) => return Err(err),
            }
        }

        Ok(res)
    }

    /// Locate SDKs installed as part of the Xcode Command Line Tools.
    ///
    /// This is a convenience method for looking for SDKs in the `SDKs` directory
    /// under the default install path for the Xcode Command Line Tools.
    ///
    /// Returns `Ok(None)` if the Xcode Command Line Tools are not present in
    /// this directory or doesn't have an `SDKs` directory.
    fn find_command_line_tools_sdks() -> Result<Option<Vec<Self>>, Error> {
        if let Some(path) = command_line_tools_sdks_directory() {
            Ok(Some(Self::find_in_directory(&path)?))
        } else {
            Ok(None)
        }
    }

    /// Obtain an [SdkPath] represent this SDK.
    fn as_sdk_path(&self) -> SdkPath {
        SdkPath {
            path: self.path().to_path_buf(),
            platform: self.platform().clone(),
            version: self.version().cloned(),
        }
    }

    /// Obtain the filesystem path to this SDK.
    fn path(&self) -> &Path {
        self.as_ref()
    }

    /// Whether this SDK path is a symlink.
    fn is_symlink(&self) -> bool;

    /// The platform this SDK is for.
    fn platform(&self) -> &Platform;

    /// Obtain the version string for this SDK.
    ///
    /// This should always be [Some] for [ParsedSdk]. It can be [None] if SDK
    /// metadata is not loaded and the version string isn't available from side-channels
    /// such as the directory name.
    fn version(&self) -> Option<&SdkVersion>;

    /// Whether this SDK supports targeting the given target name at specified OS version.
    fn supports_deployment_target(
        &self,
        target_name: &str,
        target_version: &SdkVersion,
    ) -> Result<bool, Error>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn find_system_xcode_applications() -> Result<(), Error> {
        let res = crate::find_system_xcode_applications()?;

        if PathBuf::from(XCODE_APP_DEFAULT_PATH).exists() {
            assert!(!res.is_empty());
        }

        Ok(())
    }

    #[test]
    fn find_system_xcode_developer_directories() -> Result<(), Error> {
        let res = DeveloperDirectory::find_system_xcodes()?;

        if PathBuf::from(XCODE_APP_DEFAULT_PATH).exists() {
            assert!(!res.is_empty());
        }

        Ok(())
    }

    #[test]
    fn find_all_platform_directories() -> Result<(), Error> {
        for dir in DeveloperDirectory::find_system_xcodes()? {
            for platform in dir.platforms()? {
                // Paths should agree.
                assert_eq!(
                    platform.path,
                    dir.platforms_path().join(platform.directory_name())
                );
                assert_eq!(
                    platform.path,
                    platform.path_in_developer_directory(dir.path())
                );

                // Ensure we're able to parse all platform types in existence. We want
                // this to fail when Apple introduces new platforms so we can implement
                // support for the new platform!
                assert!(!matches!(platform.platform, Platform::Unknown(_)));
            }
        }

        Ok(())
    }

    #[test]
    fn apple_platform() -> Result<(), Error> {
        assert_eq!(Platform::from_str("macosx")?, Platform::MacOsX);
        assert_eq!(Platform::from_str("MacOSX")?, Platform::MacOsX);

        Ok(())
    }

    #[test]
    fn sdk_version() -> Result<(), Error> {
        let v = SdkVersion::from("foo");
        assert!(v.normalized_version().is_err());
        assert!(v.semantic_version().is_err());

        let v = SdkVersion::from("12");
        assert_eq!(v.normalized_version()?, (12, 0, 0));
        assert_eq!(v.semantic_version()?, "12.0.0");

        let v = SdkVersion::from("12.3");
        assert_eq!(v.normalized_version()?, (12, 3, 0));
        assert_eq!(v.semantic_version()?, "12.3.0");

        let v = SdkVersion::from("12.3.1");
        assert_eq!(v.normalized_version()?, (12, 3, 1));
        assert_eq!(v.semantic_version()?, "12.3.1");

        let v = SdkVersion::from("12.3.1.2");
        assert!(v.normalized_version().is_err());

        assert_eq!(
            SdkVersion::from("12").cmp(&SdkVersion::from("11")),
            Ordering::Greater
        );
        assert_eq!(
            SdkVersion::from("12").cmp(&SdkVersion::from("12")),
            Ordering::Equal
        );
        assert_eq!(
            SdkVersion::from("12").cmp(&SdkVersion::from("13")),
            Ordering::Less
        );

        Ok(())
    }

    #[test]
    fn sdk_sorting() {
        let sorting = SdkSorting::VersionAscending;

        assert_eq!(
            sorting.compare_version(Some(&SdkVersion::from("12")), Some(&SdkVersion::from("11"))),
            Ordering::Greater
        );
        assert_eq!(
            sorting.compare_version(Some(&SdkVersion::from("11")), Some(&SdkVersion::from("12"))),
            Ordering::Less
        );

        let sorting = SdkSorting::VersionDescending;

        assert_eq!(
            sorting.compare_version(Some(&SdkVersion::from("12")), Some(&SdkVersion::from("11"))),
            Ordering::Less
        );
        assert_eq!(
            sorting.compare_version(Some(&SdkVersion::from("11")), Some(&SdkVersion::from("12"))),
            Ordering::Greater
        );
    }

    #[test]
    fn parse_sdk_path() -> Result<(), Error> {
        assert!(SdkPath::from_path("foo").is_err());
        assert!(SdkPath::from_path("foo.bar").is_err());

        let sdk = SdkPath::from_path("MacOSX.sdk")?;
        assert_eq!(sdk.platform, Platform::MacOsX);
        assert_eq!(sdk.version, None);

        let sdk = SdkPath::from_path("MacOSX12.3.sdk")?;
        assert_eq!(sdk.platform, Platform::MacOsX);
        assert_eq!(sdk.version, Some("12.3".to_string().into()));

        Ok(())
    }

    #[test]
    fn search_all() -> Result<(), Error> {
        let search = SdkSearch::default().location(SdkSearchLocation::SystemXcodes);

        search.search::<SimpleSdk>()?;

        Ok(())
    }

    /// Verifies various discovery operations on a macOS GitHub Actions runner.
    ///
    /// This assumes we're using GitHub's official macOS runners.
    #[cfg(target_os = "macos")]
    #[test]
    fn github_actions() -> Result<(), Error> {
        if std::env::var("GITHUB_ACTIONS").is_err() {
            return Ok(());
        }

        assert_eq!(
            DeveloperDirectory::default_xcode(),
            Some(DeveloperDirectory {
                path: PathBuf::from("/Applications/Xcode.app/Contents/Developer")
            })
        );
        assert!(PathBuf::from(COMMAND_LINE_TOOLS_DEFAULT_PATH).exists());

        // GitHub Actions runners have multiple Xcode applications installed.
        assert!(crate::find_system_xcode_applications()?.len() > 5);

        // We should be able to resolve developer directories for all system Xcode
        // applications.
        assert_eq!(
            crate::find_system_xcode_applications()?.len(),
            DeveloperDirectory::find_system_xcodes()?.len()
        );

        // We should be able to find SDKs for common platforms by default.
        for platform in [Platform::MacOsX, Platform::IPhoneOs, Platform::WatchOs] {
            let sdks = SdkSearch::default()
                .platform(platform)
                .search::<SimpleSdk>()?;
            assert!(!sdks.is_empty());
        }

        // We should be able to find a macOS 11.0+ SDK by default.
        let sdks = SdkSearch::default()
            .platform(Platform::MacOsX)
            .minimum_version(SdkVersion::from("11.0"))
            .search::<SimpleSdk>()?;
        assert!(!sdks.is_empty());

        Ok(())
    }
}
