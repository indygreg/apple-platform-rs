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
//! # Apple Platforms
//!
//! We model an abstract Apple platform via the [ApplePlatform] enum.
//!
//! A directory containing an Apple platform is represented by the
//! [ApplePlatformDirectory] struct.
//!
//! # Apple SDKs
//!
//! We model Apple SDKs using the [UnparsedSdk] and [ParsedSdk] types. The
//! latter requires the `parse` crate feature in order to activate support for
//! parsing JSON and plist files.
//!
//! Both these types are essentially a reference to a directory. [UnparsedSdk]
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

#[cfg(feature = "parse")]
mod parsed_sdk;
mod simple_sdk;

use std::{
    cmp::Ordering,
    collections::HashSet,
    fmt::{Display, Formatter},
    ops::Deref,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    str::FromStr,
};

pub use simple_sdk::UnparsedSdk;

#[cfg(feature = "parse")]
pub use crate::parsed_sdk::{
    AppleSdkSupportedTarget, ParsedSdk, SdkSettingsJson, SdkSettingsJsonDefaultProperties,
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
pub enum ApplePlatform {
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

impl FromStr for ApplePlatform {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AppleTVOS" => Ok(Self::AppleTvOs),
            "AppleTVSimulator" => Ok(Self::AppleTvSimulator),
            "DriverKit" => Ok(Self::DriverKit),
            "iPhoneOS" => Ok(Self::IPhoneOs),
            "iPhoneSimulator" => Ok(Self::IPhoneSimulator),
            "MacOSX" => Ok(Self::MacOsX),
            "WatchOS" => Ok(Self::WatchOs),
            "WatchSimulator" => Ok(Self::WatchSimulator),
            v => Ok(Self::Unknown(v.to_string())),
        }
    }
}

impl PartialEq for ApplePlatform {
    fn eq(&self, other: &Self) -> bool {
        self.filesystem_name().eq(other.filesystem_name())
    }
}

impl Eq for ApplePlatform {}

impl ApplePlatform {
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
/// This is just a thin abstraction over a filesystem path and an
/// [ApplePlatform] instance.
///
/// Equivalence and sorting are implemented in terms of the path component
/// only. The assumption here is the [ApplePlatform] is fully derived from the
/// filesystem path and this derivation is deterministic.
pub struct ApplePlatformDirectory {
    /// The filesystem path to this directory.
    path: PathBuf,

    /// The platform within this directory.
    platform: ApplePlatform,
}

impl ApplePlatformDirectory {
    /// Attempt to construct an instance from a filesystem path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let platform = ApplePlatform::from_platform_path(&path)?;

        Ok(Self { path, platform })
    }

    /// Find platform directories under a given developer directory.
    ///
    /// Platforms are defined by the presence of a `Platforms` directory under
    /// the developer directory. This directory layout is only recognized
    /// for modern Xcode layouts.
    ///
    /// Returns all discovered instances inside this developer directory.
    ///
    /// The return order is sorted and deterministic.
    pub fn find_in_developer_directory(
        developer_dir: impl AsRef<Path>,
    ) -> Result<Vec<Self>, Error> {
        let platforms_path = developer_dir.as_ref().join("Platforms");

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

            if let Ok(platform) = ApplePlatformDirectory::from_path(entry.path()) {
                res.push(platform);
            }
        }

        // Make deterministic.
        res.sort();

        Ok(res)
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
    /// This function is a simple wrapper around [AppleSdk::find_sdks_in_directory()] looking
    /// under the `Developer/SDKs` directory, which is where SDKs are located in platform
    /// directories.
    pub fn find_sdks<T: AppleSdk>(&self) -> Result<Vec<T>, Error> {
        T::find_sdks_in_directory(&self.sdks_path())
    }
}

impl AsRef<Path> for ApplePlatformDirectory {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<ApplePlatform> for ApplePlatformDirectory {
    fn as_ref(&self) -> &ApplePlatform {
        &self.platform
    }
}

impl Deref for ApplePlatformDirectory {
    type Target = ApplePlatform;

    fn deref(&self) -> &Self::Target {
        &self.platform
    }
}

impl PartialEq for ApplePlatformDirectory {
    fn eq(&self, other: &Self) -> bool {
        self.path.eq(&other.path)
    }
}

impl Eq for ApplePlatformDirectory {}

impl PartialOrd for ApplePlatformDirectory {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.path.partial_cmp(&other.path)
    }
}

impl Ord for ApplePlatformDirectory {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
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
    pub platform: ApplePlatform,

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

        let platform = ApplePlatform::from_str(platform_name)?;

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
    fn find_sdks_in_directory(root: &Path) -> Result<Vec<Self>, Error> {
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

    /// Locate SDKs given the path to a developer directory.
    ///
    /// This is effectively a convenience method for calling
    /// [ApplePlatformDirectory::find_in_developer_directory()] +
    /// [ApplePlatformDirectory::find_sdks()] and chaining the results.
    ///
    /// A common input path is `/Applications/Xcode.app/Contents/Developer` or the
    /// return value of [default_developer_directory()].
    fn find_developer_sdks(developer_dir: &Path) -> Result<Vec<Self>, Error> {
        Ok(
            ApplePlatformDirectory::find_in_developer_directory(developer_dir)?
                .into_iter()
                .map(|platform| Ok(platform.find_sdks()?.into_iter()))
                .collect::<Result<Vec<_>, Error>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        )
    }

    /// Discover SDKs in the default developer directory.
    ///
    /// This is a convenience function for calling [Self::find_developer_sdks()] with the output
    /// of [default_developer_directory()].
    fn find_default_developer_sdks() -> Result<Vec<Self>, Error> {
        let developer_dir = default_developer_directory()?;

        Self::find_developer_sdks(&developer_dir)
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
            Ok(Some(Self::find_sdks_in_directory(&path)?))
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
    fn platform(&self) -> &ApplePlatform;

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

/// Represents a directory to search.
///
/// We need this to annotate whether a directory is a developer directory or
/// an SDKs directory.
#[derive(Clone)]
enum SearchDirectory {
    Developer(PathBuf),
    Sdks(PathBuf),
}

impl AsRef<Path> for SearchDirectory {
    fn as_ref(&self) -> &Path {
        match self {
            Self::Developer(p) => p,
            Self::Sdks(p) => p,
        }
    }
}

impl PartialEq for SearchDirectory {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl Eq for SearchDirectory {}

impl SearchDirectory {
    /// Resolves directories containing SDKs.
    ///
    /// Will filter out directories if their platform doesn't match what we want.
    fn resolve_sdks_dirs(
        self,
        cb: &Option<SdkProgressCallback>,
        platform: &Option<ApplePlatform>,
    ) -> Result<Vec<PathBuf>, Error> {
        match self {
            Self::Developer(developer_dir) => {
                if let Some(cb) = cb {
                    cb(SdkSearchEvent::DeveloperDirectoryFindPlatforms(
                        developer_dir.clone(),
                    ));
                }

                Ok(
                    ApplePlatformDirectory::find_in_developer_directory(developer_dir)?
                        .into_iter()
                        .filter_map(|platform_dir| {
                            if let Some(wanted_platform) = &platform {
                                if &platform_dir.platform == wanted_platform {
                                    if let Some(cb) = cb {
                                        cb(SdkSearchEvent::PlatformDirectoryInclude(
                                            platform_dir.path.clone(),
                                        ));
                                    }
                                    Some(platform_dir.sdks_path())
                                } else {
                                    if let Some(cb) = cb {
                                        cb(SdkSearchEvent::PlatformDirectoryExclude(
                                            platform_dir.path,
                                        ));
                                    }
                                    None
                                }
                            } else {
                                if let Some(cb) = cb {
                                    cb(SdkSearchEvent::PlatformDirectoryInclude(
                                        platform_dir.path.clone(),
                                    ));
                                }
                                Some(platform_dir.sdks_path())
                            }
                        })
                        .collect::<Vec<_>>(),
                )
            }
            Self::Sdks(path) => Ok(vec![path]),
        }
    }
}

/// Sorting strategy to apply to SDK searches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdkSorting {
    /// Do not apply any sorting.
    ///
    /// This will return SDKs in the order they are discovered from the input
    /// paths.
    None,

    /// Order SDKs by their version in descending order.
    ///
    /// Newer SDKs will come before older SDKs.
    VersionDescending,

    /// Order SDKs by their version in ascending order.
    ///
    /// Older SDKs will come before newer SDKs.
    VersionAscending,
}

impl Display for SdkSorting {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "nothing",
            Self::VersionDescending => "descending version",
            Self::VersionAscending => "ascending version",
        })
    }
}

impl SdkSorting {
    pub fn compare_version(&self, a: Option<&SdkVersion>, b: Option<&SdkVersion>) -> Ordering {
        match self {
            Self::None => Ordering::Equal,
            Self::VersionAscending => match (a, b) {
                (Some(a), Some(b)) => a.cmp(b),
                (Some(_), None) => Ordering::Greater,
                (None, Some(_)) => Ordering::Less,
                (None, None) => Ordering::Equal,
            },
            Self::VersionDescending => match (a, b) {
                (Some(a), Some(b)) => b.cmp(a),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
        }
    }
}

/// Describes an event during SDK discovery.
///
/// This events are sent to the progress callback to allow monitoring and debugging
/// of SDK searching activity.
pub enum SdkSearchEvent {
    SdkRootEnvLoad(String),
    DeveloperDirectoryFindPlatforms(PathBuf),
    PlatformDirectoryInclude(PathBuf),
    PlatformDirectoryExclude(PathBuf),
    SearchingDeveloperDirectory(PathBuf),
    SearchingSdksDirectory(PathBuf),
    SdkFilterMatch(SdkPath),
    SdkFilterExclude(SdkPath, String),
    Sorting(usize, SdkSorting),
}

impl Display for SdkSearchEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SdkRootEnvLoad(path) => {
                f.write_fmt(format_args!("loading SDK from SDKROOT: {}", path))
            }
            Self::DeveloperDirectoryFindPlatforms(path) => f.write_fmt(format_args!(
                "finding platforms in Developer Directory {}",
                path.display()
            )),
            Self::SearchingDeveloperDirectory(path) => f.write_fmt(format_args!(
                "searching Developer Directory {}",
                path.display()
            )),
            Self::PlatformDirectoryInclude(path) => f.write_fmt(format_args!(
                "searching Platform directory {}",
                path.display()
            )),
            Self::PlatformDirectoryExclude(path) => f.write_fmt(format_args!(
                "excluding Platform directory {}",
                path.display()
            )),
            Self::SearchingSdksDirectory(path) => {
                f.write_fmt(format_args!("searching SDKs directory {}", path.display()))
            }
            Self::SdkFilterMatch(sdk) => {
                f.write_fmt(format_args!("SDK {} matches search filter", sdk))
            }
            Self::SdkFilterExclude(sdk, reason) => {
                f.write_fmt(format_args!("SDK {} discarded because {}", sdk, reason))
            }
            Self::Sorting(count, sorting) => {
                f.write_fmt(format_args!("sorting {} SDKs by {}", count, sorting))
            }
        }
    }
}

/// A callable that receives progress during an SDK search.
pub type SdkProgressCallback = fn(SdkSearchEvent);

/// Search parameters for locating an Apple SDK.
///
/// This type can be used to construct a search for an Apple SDK given user chosen
/// search parameters.
///
/// The search algorithm is essentially:
///
/// 1. Collect directories to search.
/// 2. Iterate through each directory to discover, filter, and sort SDKs.
/// 3. Globally sort (if enabled).
///
/// The caller can specify multiple directories to search. The order of their search
/// (in terms of methods to enable each) is:
///
/// 1. [Self::sdk_root_env()]
/// 2. [Self::developer_dir()]
/// 3. [Self::command_line_tools()]
/// 4. [Self::default_system_xcode()]
/// 5. [Self::system_xcodes()]
/// 6. [Self::additional_developer_dir()]
/// 7. [Self::additional_sdks_dir()]
///
/// There are additional parameters to control filtering of SDKs:
///
/// * [Self::platform()]
/// * [Self::minimum_version()]
/// * [Self::maximum_version()]
/// * [Self::deployment_target()]
///
/// By default, no filtering is performed. This means all SDKs in all search locations
/// for all platforms are returned.
///
/// If you are looking for an SDK to use, you probably want to at least use a
/// platform filter. Otherwise you may see SDKs for platforms you aren't targeting.
#[derive(Clone)]
pub struct SdkSearch {
    progress_callback: Option<SdkProgressCallback>,
    search_sdkroot_env: bool,
    search_developer_dir: bool,
    search_command_line_tools_sdks: bool,
    search_default_system_xcode: bool,
    search_system_xcodes: bool,
    search_additional_developer_dirs: Vec<PathBuf>,
    search_additional_sdks_dirs: Vec<PathBuf>,
    platform: Option<ApplePlatform>,
    minimum_version: Option<SdkVersion>,
    maximum_version: Option<SdkVersion>,
    deployment_target: Option<(String, SdkVersion)>,
    sorting: SdkSorting,
}

impl Default for SdkSearch {
    fn default() -> Self {
        Self {
            progress_callback: None,
            search_sdkroot_env: true,
            search_developer_dir: true,
            search_command_line_tools_sdks: false,
            search_default_system_xcode: false,
            search_system_xcodes: false,
            search_additional_developer_dirs: vec![],
            search_additional_sdks_dirs: vec![],
            platform: None,
            minimum_version: None,
            maximum_version: None,
            deployment_target: None,
            sorting: SdkSorting::None,
        }
    }
}

impl SdkSearch {
    /// Define a function that will be called to provide updates on SDK search status.
    pub fn progress_callback(mut self, callback: SdkProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// Whether to resolve an SDK as specified by the `SDKROOT` environment variable.
    ///
    /// If set, we will attempt to resolve the SDK as specified via the `SDKRoot`
    /// environment variable. If the environment variable is set and it doesn't point
    /// to a valid SDK, the search will yield an error. Contrast with other search
    /// locations which will typically ignore failures if a location does not exist.
    ///
    /// Default is `true`.
    pub fn sdk_root_env(mut self, value: bool) -> Self {
        self.search_sdkroot_env = value;
        self
    }

    /// Whether to search the current/default developer directory.
    ///
    /// This effectively controls whether the path resolved by [default_developer_directory()]
    /// will be searched, if available. This will honor the `DEVELOPER_DIR` environment
    /// variable to override the default path.
    ///
    /// Default is `true`.
    pub fn developer_dir(mut self, value: bool) -> Self {
        self.search_developer_dir = value;
        self
    }

    /// Whether to search the Xcode Command Line Tools installation.
    ///
    /// This effectively controls whether the path resolved by
    /// [command_line_tools_sdks_directory()] will be searched, if available.
    ///
    /// Default is `false`.
    pub fn command_line_tools(mut self, value: bool) -> Self {
        self.search_command_line_tools_sdks = value;
        self
    }

    /// Whether to search the developer directory in the default Xcode app.
    ///
    /// This effectively controls whether the path resolved by [default_xcode_developer_directory()]
    /// will be searched, if available.
    ///
    /// Default is `false`.
    pub fn default_system_xcode(mut self, value: bool) -> Self {
        self.search_default_system_xcode = value;
        self
    }

    /// Whether to search the developer directory in all system installed Xcode applications.
    ///
    /// This effectively controls whether the paths resolved by
    /// [find_system_xcode_developer_directories()] will be searched, if present.
    ///
    /// Many macOS systems only have a single Xcode application under
    /// `/Applications/Xcode.app`. However, environments like CI workers and developers
    /// who have beta versions of Xcode installed may have multiple versions of Xcode
    /// available.
    ///
    /// Default is `false`.
    pub fn system_xcodes(mut self, value: bool) -> Self {
        self.search_system_xcodes = value;
        self
    }

    /// Register an additional *Developer Directory* to search.
    ///
    /// SDKs exist under a `Platforms/*.platform/Developer/SDKs` child directory.
    pub fn additional_developer_dir(mut self, value: impl AsRef<Path>) -> Self {
        self.search_additional_developer_dirs
            .push(value.as_ref().to_path_buf());
        self
    }

    /// Register an additional SDKs directory to search.
    ///
    /// This is a directory holding SDKs. e.g. `*.sdk` sub-directories.
    pub fn additional_sdks_dir(mut self, value: impl AsRef<Path>) -> Self {
        self.search_additional_sdks_dirs
            .push(value.as_ref().to_path_buf());
        self
    }

    /// Set the SDK platform to search for.
    ///
    /// If you do not call this, SDKs for all platforms are returned.
    ///
    /// If you are looking for a specific SDK to use, you probably want to call this.
    /// If you are searching for all available SDKs, you probably don't want to call this.
    pub fn platform(mut self, platform: ApplePlatform) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Minimum SDK version to require.
    ///
    /// Effectively imposes a `>=` filter on found SDKs.
    ///
    /// If using [UnparsedSdk] and the SDK version could not be determined from
    /// the filesystem path, the version is assumed to be `0.0` and this filter
    /// will likely exclude the SDK.
    pub fn minimum_version(mut self, version: SdkVersion) -> Self {
        self.minimum_version = Some(version);
        self
    }

    /// Maximum SDK version to return.
    ///
    /// Effectively imposes a `<=` filter on found SDKs.
    pub fn maximum_version(mut self, version: SdkVersion) -> Self {
        self.maximum_version = Some(version);
        self
    }

    /// Deployment target that the SDK must support.
    ///
    /// When set, only SDKs that support targeting the given target-version pair will
    /// be returned. Example values are (`macosx`, `10.15`).
    ///
    /// Only modern SDKs with `SDKSettings.json` files advertise their targeting settings
    /// in a way that allows this filter to work.
    ///
    /// Attempting to use this filter on [UnparsedSdk] will result in a run-time
    /// error at search time since these SDKs do not parse `SDKSettings` files.
    pub fn deployment_target(mut self, target: String, version: SdkVersion) -> Self {
        self.deployment_target = Some((target, version));
        self
    }

    /// Define the sorting order for returned SDKs.
    ///
    /// Default is [SdkSorting::None].
    pub fn sorting(mut self, sorting: SdkSorting) -> Self {
        self.sorting = sorting;
        self
    }

    /// Perform a search, yielding found SDKs sorted by the search's preferences.
    ///
    /// May return an empty vector.
    ///
    /// Consumes the search instance.
    pub fn search<SDK: AppleSdk>(self) -> Result<Vec<SDK>, Error> {
        // Collect directories to search.
        let mut search_dirs = vec![];

        // Ensure we only search each directory once.
        let mut append_dir = |v: SearchDirectory| {
            if !search_dirs.contains(&v) {
                search_dirs.push(v);
            }
        };

        if self.search_developer_dir {
            if let Ok(path) = default_developer_directory() {
                append_dir(SearchDirectory::Developer(path));
            }
        }

        if self.search_command_line_tools_sdks {
            if let Some(path) = command_line_tools_sdks_directory() {
                append_dir(SearchDirectory::Sdks(path));
            }
        }

        if self.search_default_system_xcode {
            if let Some(path) = default_xcode_developer_directory() {
                append_dir(SearchDirectory::Developer(path));
            }
        }

        if self.search_system_xcodes {
            if let Ok(paths) = find_system_xcode_developer_directories() {
                for path in paths {
                    append_dir(SearchDirectory::Developer(path));
                }
            }
        }

        for path in &self.search_additional_developer_dirs {
            append_dir(SearchDirectory::Developer(path.clone()));
        }

        for path in &self.search_additional_sdks_dirs {
            append_dir(SearchDirectory::Sdks(path.clone()));
        }

        let mut searched_dirs = HashSet::new();

        let mut res = vec![];

        // SDKROOT is handled specially since it isn't a collection of directories
        // and failures are fatal.
        if self.search_sdkroot_env {
            if let Some(env) = std::env::var_os("SDKROOT") {
                if let Some(cb) = &self.progress_callback {
                    cb(SdkSearchEvent::SdkRootEnvLoad(
                        env.to_string_lossy().to_string(),
                    ));
                }

                let sdk = SDK::from_directory(&PathBuf::from(env))?;

                if self.filter_sdk(&sdk, &self.progress_callback)? {
                    res.push(sdk);
                }
            }
        }

        for search_dir in search_dirs {
            for sdk_dir in search_dir.resolve_sdks_dirs(&self.progress_callback, &self.platform)? {
                // Avoid redundant work.
                if searched_dirs.contains(&sdk_dir) {
                    continue;
                }

                searched_dirs.insert(sdk_dir.clone());

                if let Some(cb) = &self.progress_callback {
                    cb(SdkSearchEvent::SearchingSdksDirectory(sdk_dir.clone()));
                }

                for sdk in SDK::find_sdks_in_directory(&sdk_dir)? {
                    if self.filter_sdk(&sdk, &self.progress_callback)? {
                        res.push(sdk);
                    }
                }
            }
        }

        // Sorting should be stable with None variant. But we can avoid the
        // overhead.
        if self.sorting != SdkSorting::None {
            res.sort_by(|a, b| self.sorting.compare_version(a.version(), b.version()))
        }

        Ok(res)
    }

    /// Whether an SDK matches our search filter.
    pub fn filter_sdk<SDK: AppleSdk>(
        &self,
        sdk: &SDK,
        cb: &Option<SdkProgressCallback>,
    ) -> Result<bool, Error> {
        let sdk_path = sdk.as_sdk_path();

        if let Some(wanted_platform) = &self.platform {
            if sdk.platform() != wanted_platform {
                if let Some(cb) = cb {
                    cb(SdkSearchEvent::SdkFilterExclude(
                        sdk_path,
                        format!(
                            "platform {} != {}",
                            sdk.platform().filesystem_name(),
                            wanted_platform.filesystem_name()
                        ),
                    ));
                }

                return Ok(false);
            }
        }

        if let Some(min_version) = &self.minimum_version {
            if let Some(sdk_version) = sdk.version() {
                if sdk_version < min_version {
                    if let Some(cb) = cb {
                        cb(SdkSearchEvent::SdkFilterExclude(
                            sdk_path,
                            format!(
                                "SDK version {} < minimum version {}",
                                sdk_version, min_version
                            ),
                        ));
                    }

                    return Ok(false);
                }
            } else {
                // SDKs without a version always fail.
                if let Some(cb) = cb {
                    cb(SdkSearchEvent::SdkFilterExclude(
                        sdk_path,
                        format!(
                            "Unknown SDK version fails to meet minimum version {}",
                            min_version
                        ),
                    ));
                }

                return Ok(false);
            }
        }

        if let Some(max_version) = &self.maximum_version {
            if let Some(sdk_version) = sdk.version() {
                if sdk_version > max_version {
                    if let Some(cb) = cb {
                        cb(SdkSearchEvent::SdkFilterExclude(
                            sdk_path,
                            format!(
                                "SDK version {} > maximum version {}",
                                sdk_version, max_version
                            ),
                        ));
                    }

                    return Ok(false);
                }
            } else {
                // SDKs without a version always fail.

                if let Some(cb) = cb {
                    cb(SdkSearchEvent::SdkFilterExclude(
                        sdk_path,
                        format!(
                            "Unknown SDK version fails to meet maximum version {}",
                            max_version
                        ),
                    ));
                }

                return Ok(false);
            }
        }

        if let Some((target, version)) = &self.deployment_target {
            if !sdk.supports_deployment_target(target, version)? {
                if let Some(cb) = cb {
                    cb(SdkSearchEvent::SdkFilterExclude(
                        sdk_path,
                        format!("does not support deployment target {}:{}", target, version),
                    ));
                }

                return Ok(false);
            }
        }

        if let Some(cb) = cb {
            cb(SdkSearchEvent::SdkFilterMatch(sdk_path));
        }

        Ok(true)
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

    #[test]
    fn find_all_platform_directories() -> Result<(), Error> {
        for path in find_system_xcode_developer_directories()? {
            for platform in ApplePlatformDirectory::find_in_developer_directory(&path)? {
                // Paths should agree.
                assert_eq!(
                    platform.path,
                    path.join("Platforms").join(platform.directory_name())
                );
                assert_eq!(platform.path, platform.path_in_developer_directory(&path));

                // Ensure we're able to parse all platform types in existence. We want
                // this to fail when Apple introduces new platforms so we can implement
                // support for the new platform!
                assert!(!matches!(platform.platform, ApplePlatform::Unknown(_)));
            }
        }

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
        assert_eq!(sdk.platform, ApplePlatform::MacOsX);
        assert_eq!(sdk.version, None);

        let sdk = SdkPath::from_path("MacOSX12.3.sdk")?;
        assert_eq!(sdk.platform, ApplePlatform::MacOsX);
        assert_eq!(sdk.version, Some("12.3".to_string().into()));

        Ok(())
    }

    #[test]
    fn search_all() -> Result<(), Error> {
        let search = SdkSearch::default()
            .command_line_tools(true)
            .system_xcodes(true);

        search.search::<UnparsedSdk>()?;

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

        // We should be able to find SDKs for common platforms by default.
        for platform in [
            ApplePlatform::MacOsX,
            ApplePlatform::IPhoneOs,
            ApplePlatform::WatchOs,
        ] {
            let sdks = SdkSearch::default()
                .platform(platform)
                .search::<UnparsedSdk>()?;
            assert!(!sdks.is_empty());
        }

        // We should be able to find a macOS 11.0+ SDK by default.
        let sdks = SdkSearch::default()
            .platform(ApplePlatform::MacOsX)
            .minimum_version(SdkVersion::from("11.0"))
            .search::<UnparsedSdk>()?;
        assert!(!sdks.is_empty());

        Ok(())
    }
}
