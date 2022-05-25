use {
    crate::Error,
    std::path::{Path, PathBuf},
};

#[cfg(feature = "parse")]
use crate::parsed_sdk::ParsedSdk;

/// A directory purported to hold an Apple SDK.
#[derive(Clone, Debug)]
pub struct UnparsedSdk {
    /// Root directory of the SDK.
    pub path: PathBuf,

    /// Whether the root directory is a symlink to another path.
    pub is_symlink: bool,
}

impl UnparsedSdk {
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
    pub fn try_parse(self) -> Result<ParsedSdk, Error> {
        self.try_into()
    }
}
