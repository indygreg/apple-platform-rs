use {
    crate::{
        command_line_tools_sdks_directory, AppleSdk, DeveloperDirectory, Error, Platform,
        PlatformDirectory, SdkPath, SdkVersion,
    },
    std::{
        cmp::Ordering,
        collections::HashSet,
        fmt::{Display, Formatter},
        path::PathBuf,
    },
};

/// The search location that a [SdkSearchLocation] normalizes to.
enum SdkSearchResolvedLocation {
    /// Nothing.
    None,
    /// A collection of platform directories.
    PlatformDirectories(Vec<PlatformDirectory>),
    /// A directory holding SDKs.
    SdksDirectory(PathBuf),
    /// A specific directory with an SDK.
    SdkDirectory(PathBuf),
    /// A specified directory with an SDK excluded from SDK filtering.
    SdkDirectoryUnfiltered(PathBuf),
}

impl SdkSearchResolvedLocation {
    fn apply_sdk_filter(&self) -> bool {
        !matches!(self, Self::SdkDirectoryUnfiltered(_))
    }
}

/// Represents a location to search for SDKs.
#[derive(Clone, Debug)]
pub enum SdkSearchLocation {
    /// Use the path specified by the `SDKROOT` environment variable.
    ///
    /// If this environment variable is defined and the path is not valid, an error
    /// occurs.
    ///
    /// If this location yields an SDK, the SDK search will be aborted and subsequent
    /// locations will not be searched. This effectively honors the intent of `SDKROOT`
    /// to force usage of a given SDK.
    ///
    /// If this behavior is not desirable, construct an [SdkSearch] with a
    /// [SdkSearchLocation::Sdk] using the value of `SDKROOT`.
    SdkRootEnv,

    /// Use the Developer Directory specified by the `DEVELOPER_DIR` environment variable.
    ///
    /// If this environment variable is defined and the path is not valid, an error
    /// occurs.
    ///
    /// If this location yields an SDK, the SDK search will be aborted and subsequent
    /// locations will not be searched. This effectively honors the intent of `DEVELOPER_DIR`
    /// to explicitly define a developer directory to use for SDK searching.
    ///
    /// If this behavior is not desirable, construct an [SdkSearch] with a
    /// [SdkSearchLocation::Developer] using the value of `DEVELOPER_DIR`.
    DeveloperDirEnv,

    /// Look for SDKs within the system installed `Xcode` application.
    ///
    /// This effectively controls whether the Developer Directory resolved by
    /// [DeveloperDirectory::default_xcode()] will be searched, if available.
    SystemXcode,

    /// Look for SDKs within the system install `Xcode Command Line Tools` installation.
    ///
    /// This effectively uses the directory returned by [command_line_tools_sdks_directory()],
    /// if available.
    CommandLineTools,

    /// Invoke `xcode-select` to find a *Developer Directory* to search.
    ///
    /// This mechanism is intended as a fallback in case other (pure Rust) mechanisms for locating
    /// the default *Developer Directory* fail. If you find yourself needing this, it likely
    /// points to a gap in our feature coverage to locate the default *Developer Directory* without
    /// running external tools. Consider filing a bug against this crate to track closing the
    /// feature gap.
    XcodeSelect,

    /// Look for SDKs within all system installed `Xcode` applications.
    ///
    /// This effectively controls whether the paths resolved by
    /// [DeveloperDirectory::find_system_xcodes()] will be searched, if present.
    ///
    /// Many macOS systems only have a single Xcode application at `/Applications/Xcode.app`.
    /// However, environments like CI workers and developers having beta versions of Xcode installed
    /// may have multiple versions of Xcode available. This option can enable multiple copies
    /// of Xcode to be used.
    SystemXcodes,

    /// Use an explicit *Developer Directory*.
    ///
    /// This can be used to point a search at a non-standard location holding a *Developer
    /// Directory*. A common use case for this is when cross-compiling or using hermetic / chroot /
    /// container build environments that don't resemble a common macOS system layout and therefore
    /// prohibit use of mechanisms for locating a *Developer Directory* in default locations.
    Developer(DeveloperDirectory),

    /// Use an explicit directory holding SDKs.
    ///
    /// This is similar to [Self::Developer] with regards to its intended use cases. The difference
    /// is the path is a directory holding `*.sdk` directories, not a *Developer Directory*.
    Sdks(PathBuf),

    /// Use an explicit directory holding an SDK.
    Sdk(PathBuf),
}

impl Display for SdkSearchLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SdkRootEnv => f.write_str("SDKROOT environment variable"),
            Self::DeveloperDirEnv => f.write_str("DEVELOPER_DIR environment variable"),
            Self::SystemXcode => f.write_str("System-installed Xcode application"),
            Self::CommandLineTools => f.write_str("Xcode Command Line Tools installation"),
            Self::XcodeSelect => f.write_str("xcode-select"),
            Self::SystemXcodes => f.write_str("All system-installed Xcode applications"),
            Self::Developer(dir) => {
                f.write_fmt(format_args!("Developer Directory {}", dir.path().display()))
            }
            Self::Sdks(path) => f.write_fmt(format_args!("SDKs directory {}", path.display())),
            Self::Sdk(path) => f.write_fmt(format_args!("SDK directory {}", path.display())),
        }
    }
}

impl SdkSearchLocation {
    /// Whether this search location is terminal.
    fn is_terminal(&self) -> bool {
        matches!(self, Self::SdkRootEnv | Self::DeveloperDirEnv)
    }

    fn resolve_location(&self) -> Result<SdkSearchResolvedLocation, Error> {
        match self {
            Self::SdkRootEnv => {
                if let Some(path) = std::env::var_os("SDKROOT") {
                    let path = PathBuf::from(path);

                    if path.exists() {
                        Ok(SdkSearchResolvedLocation::SdkDirectoryUnfiltered(path))
                    } else {
                        Err(Error::PathNotSdk(path))
                    }
                } else {
                    Ok(SdkSearchResolvedLocation::None)
                }
            }
            Self::DeveloperDirEnv => {
                if let Some(dir) = DeveloperDirectory::from_env()? {
                    Ok(SdkSearchResolvedLocation::PlatformDirectories(
                        dir.platforms()?,
                    ))
                } else {
                    Ok(SdkSearchResolvedLocation::None)
                }
            }
            Self::SystemXcode => {
                if let Some(dir) = DeveloperDirectory::default_xcode() {
                    Ok(SdkSearchResolvedLocation::PlatformDirectories(
                        dir.platforms()?,
                    ))
                } else {
                    Ok(SdkSearchResolvedLocation::None)
                }
            }
            Self::CommandLineTools => {
                if let Some(path) = command_line_tools_sdks_directory() {
                    Ok(SdkSearchResolvedLocation::SdksDirectory(path))
                } else {
                    Ok(SdkSearchResolvedLocation::None)
                }
            }
            Self::XcodeSelect => Ok(SdkSearchResolvedLocation::PlatformDirectories(
                DeveloperDirectory::from_xcode_select()?.platforms()?,
            )),
            Self::SystemXcodes => Ok(SdkSearchResolvedLocation::PlatformDirectories(
                DeveloperDirectory::find_system_xcodes()?
                    .into_iter()
                    .map(|dir| dir.platforms())
                    .collect::<Result<Vec<_>, Error>>()?
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>(),
            )),
            Self::Developer(dir) => Ok(SdkSearchResolvedLocation::PlatformDirectories(
                dir.platforms()?,
            )),
            Self::Sdks(path) => Ok(SdkSearchResolvedLocation::SdksDirectory(path.clone())),
            Self::Sdk(path) => Ok(SdkSearchResolvedLocation::SdkDirectory(path.clone())),
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
    /// Beginning a search of a given location.
    SearchingLocation(SdkSearchLocation),
    PlatformDirectoryInclude(PathBuf),
    PlatformDirectoryExclude(PathBuf),
    SdkFilterSkip(SdkPath),
    SdkFilterMatch(SdkPath),
    SdkFilterExclude(SdkPath, String),
    Sorting(usize, SdkSorting),
}

impl Display for SdkSearchEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SearchingLocation(location) => {
                f.write_fmt(format_args!("searching {}", location))
            }
            Self::PlatformDirectoryInclude(path) => f.write_fmt(format_args!(
                "searching Platform directory {}",
                path.display()
            )),
            Self::PlatformDirectoryExclude(path) => f.write_fmt(format_args!(
                "excluding Platform directory {}",
                path.display()
            )),
            Self::SdkFilterSkip(sdk) => f.write_fmt(format_args!("SDK {} bypasses filter", sdk)),
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
/// 1. Iterate through each registered search location.
/// 2. Discover candidate SDKs and filter.
/// 3. Globally sort (if enabled).
///
/// # Search Locations
///
/// Search mechanisms / locations are represented via [SdkSearchLocation] and internally
/// the searcher maintains a vector of locations. The default search locations are:
///
/// 1. Use path specified by `SDKROOT` environment variable, if defined.
/// 2. Find SDKs within the Developer Directory defined by the `DEVELOPER_DIR` environment
///    variable.
/// 3. Find SDKs within the system installed `Xcode` application.
/// 4. Find SDKs within the system installed Xcode Command Line Tools.
///
/// Simply call [Self::location()] to register a new location. If the default locations
/// are not desirable, construct an empty instance via [Self::empty()] and register your
/// explicit list of locations.
///
/// An attempt is made to only search a given location at most once. This is done in
/// order to avoid redundant work. If a location is specified multiple times - even via
/// different [SdkSearchLocation] variants - subsequent searches of that location will
/// yield no distinct results. Duplicate SDKs can occur in the returned list.
///
/// # Filtering
///
/// Filters can be registered to control which SDKs are emitted from the search.
///
/// By default, no filtering is performed. This means all SDKs in all search locations
/// are returned. This can return SDKs belonging to multiple platforms (e.g. macOS and iOS).
///
/// The following functions control filtering:
///
/// * [Self::platform()]
/// * [Self::minimum_version()]
/// * [Self::maximum_version()]
/// * [Self::deployment_target()]
///
/// If you are looking for an SDK to use (e.g. for compilation), you should at least use a
/// platform filter. Otherwise you may see SDKs for platforms you aren't targeting! It is
/// also an encouraged practice to specify a minimum or maximum SDK version to use.
///
/// If you know you are targeting a specific OS version, applying a targeting filter
/// via [Self::deployment_target()] is recommended. However, this filter is not always
/// reliable. See the caveats in its documentation.
///
/// # Sorting
///
/// By default, the returned list of SDKs is the chained result of SDKs discovered
/// in all registered search locations. The order of the SDK within each search
/// location is likely the sorted order of directory names as they appear on the filesystem.
///
/// If using an SDK for compilation, sorting by the SDK version is likely desired.
/// Using the latest/newest SDK that supports a given deployment target is generally
/// a best practice.
#[derive(Clone)]
pub struct SdkSearch {
    progress_callback: Option<SdkProgressCallback>,
    locations: Vec<SdkSearchLocation>,
    platform: Option<Platform>,
    minimum_version: Option<SdkVersion>,
    maximum_version: Option<SdkVersion>,
    deployment_target: Option<(String, SdkVersion)>,
    sorting: SdkSorting,
}

impl Default for SdkSearch {
    fn default() -> Self {
        Self {
            progress_callback: None,
            locations: vec![
                SdkSearchLocation::SdkRootEnv,
                SdkSearchLocation::DeveloperDirEnv,
                SdkSearchLocation::SystemXcode,
                SdkSearchLocation::CommandLineTools,
            ],
            platform: None,
            minimum_version: None,
            maximum_version: None,
            deployment_target: None,
            sorting: SdkSorting::None,
        }
    }
}

impl SdkSearch {
    /// Obtain an instance with an empty set of search locations.
    ///
    /// The search will not resolve any SDKs unless a search location is registered
    /// with the instance.
    pub fn empty() -> Self {
        let mut s = Self::default();
        s.locations.clear();
        s
    }

    /// Define a function that will be called to provide updates on SDK search status.
    pub fn progress_callback(mut self, callback: SdkProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// Add a location to search.
    ///
    /// The location will be appended to the current search location list.
    pub fn location(mut self, location: SdkSearchLocation) -> Self {
        self.locations.push(location);
        self
    }

    /// Set the SDK platform to search for.
    ///
    /// If you do not call this, SDKs for all platforms are returned.
    ///
    /// If you are looking for a specific SDK to use, you probably want to call this.
    /// If you are searching for all available SDKs, you probably don't want to call this.
    pub fn platform(mut self, platform: Platform) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Minimum SDK version to require.
    ///
    /// Effectively imposes a `>=` filter on found SDKs.
    ///
    /// If using `SimpleSdk` and the SDK version could not be determined from
    /// the filesystem path, the version is assumed to be `0.0` and this filter
    /// will likely exclude the SDK.
    pub fn minimum_version(mut self, version: impl Into<SdkVersion>) -> Self {
        self.minimum_version = Some(version.into());
        self
    }

    /// Maximum SDK version to return.
    ///
    /// Effectively imposes a `<=` filter on found SDKs.
    pub fn maximum_version(mut self, version: impl Into<SdkVersion>) -> Self {
        self.maximum_version = Some(version.into());
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
    /// Attempting to use this filter on `SimpleSdk` will result in a run-time
    /// error at search time since these SDKs do not parse `SDKSettings` files.
    pub fn deployment_target(
        mut self,
        target: impl ToString,
        version: impl Into<SdkVersion>,
    ) -> Self {
        self.deployment_target = Some((target.to_string(), version.into()));
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
    pub fn search<SDK: AppleSdk>(&self) -> Result<Vec<SDK>, Error> {
        let mut sdks = vec![];

        // Track searched locations to avoid redundant work.
        let mut searched_platform_dirs = HashSet::new();
        let mut searched_sdks_dirs = HashSet::new();

        for location in &self.locations {
            if let Some(cb) = &self.progress_callback {
                cb(SdkSearchEvent::SearchingLocation(location.clone()));
            }

            // Expand each location to SDKs.
            let resolved = location.resolve_location()?;

            let candidate_sdks = match &resolved {
                SdkSearchResolvedLocation::None => {
                    vec![]
                }
                SdkSearchResolvedLocation::PlatformDirectories(dirs) => dirs
                    .iter()
                    // Apply platform filter.
                    .filter(|dir| {
                        if let Some(wanted_platform) = &self.platform {
                            if &dir.platform == wanted_platform {
                                if let Some(cb) = &self.progress_callback {
                                    cb(SdkSearchEvent::PlatformDirectoryInclude(dir.path.clone()));
                                }

                                true
                            } else {
                                if let Some(cb) = &self.progress_callback {
                                    cb(SdkSearchEvent::PlatformDirectoryExclude(dir.path.clone()));
                                }

                                false
                            }
                        } else {
                            if let Some(cb) = &self.progress_callback {
                                cb(SdkSearchEvent::PlatformDirectoryInclude(dir.path.clone()));
                            }

                            true
                        }
                    })
                    // Apply duplicate search filter.
                    .filter(|dir| {
                        if searched_platform_dirs.contains(dir.path()) {
                            false
                        } else {
                            searched_platform_dirs.insert(dir.path().to_path_buf());
                            true
                        }
                    })
                    .map(|dir| dir.find_sdks::<SDK>())
                    .collect::<Result<Vec<_>, Error>>()?
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>(),
                SdkSearchResolvedLocation::SdksDirectory(path) => {
                    if searched_sdks_dirs.contains(path) {
                        vec![]
                    } else {
                        searched_sdks_dirs.insert(path.clone());
                        SDK::find_in_directory(path)?
                    }
                }
                SdkSearchResolvedLocation::SdkDirectory(path)
                | SdkSearchResolvedLocation::SdkDirectoryUnfiltered(path) => {
                    vec![SDK::from_directory(path)?]
                }
            };

            let mut added_count = 0;

            for sdk in candidate_sdks {
                let include = if resolved.apply_sdk_filter() {
                    self.filter_sdk(&sdk)?
                } else {
                    if let Some(cb) = &self.progress_callback {
                        cb(SdkSearchEvent::SdkFilterSkip(sdk.as_sdk_path()));
                    }

                    true
                };

                if include {
                    sdks.push(sdk);
                    added_count += 1;
                }
            }

            if location.is_terminal() && added_count > 0 {
                break;
            }
        }

        // Sorting should be stable with None variant. But we can avoid the
        // overhead.
        if self.sorting != SdkSorting::None {
            sdks.sort_by(|a, b| self.sorting.compare_version(a.version(), b.version()))
        }

        Ok(sdks)
    }

    /// Whether an SDK matches our search filter.
    ///
    /// This is exposed as a convenience method to allow custom implementations of
    /// SDK searching using the filtering logic on this type.
    pub fn filter_sdk<SDK: AppleSdk>(&self, sdk: &SDK) -> Result<bool, Error> {
        let sdk_path = sdk.as_sdk_path();

        if let Some(wanted_platform) = &self.platform {
            if sdk.platform() != wanted_platform {
                if let Some(cb) = &self.progress_callback {
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
                    if let Some(cb) = &self.progress_callback {
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
                if let Some(cb) = &self.progress_callback {
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
                    if let Some(cb) = &self.progress_callback {
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

                if let Some(cb) = &self.progress_callback {
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
                if let Some(cb) = &self.progress_callback {
                    cb(SdkSearchEvent::SdkFilterExclude(
                        sdk_path,
                        format!("does not support deployment target {}:{}", target, version),
                    ));
                }

                return Ok(false);
            }
        }

        if let Some(cb) = &self.progress_callback {
            cb(SdkSearchEvent::SdkFilterMatch(sdk_path));
        }

        Ok(true)
    }
}
