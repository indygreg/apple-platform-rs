use {
    crate::{AppleSdk, Error},
    std::path::{Path, PathBuf},
};

#[cfg(feature = "parse")]
use crate::parsed_sdk::ParsedSdk;

/// A directory purported to hold an Apple SDK.
#[derive(Clone, Debug)]
pub struct UnparsedSdk {
    /// Root directory of the SDK.
    path: PathBuf,

    /// Whether the root directory is a symlink to another path.
    is_symlink: bool,
}

impl AsRef<Path> for UnparsedSdk {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AppleSdk for UnparsedSdk {
    fn from_directory(path: &Path) -> Result<Self, Error> {
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

    fn is_symlink(&self) -> bool {
        self.is_symlink
    }
}

impl UnparsedSdk {
    #[cfg(feature = "parse")]
    /// Attempt to convert into an [AppleSdk] by parsing an `SDKSettings.*` file.
    pub fn try_parse(self) -> Result<ParsedSdk, Error> {
        self.try_into()
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::{default_developer_directory, COMMAND_LINE_TOOLS_DEFAULT_PATH},
    };

    #[test]
    fn test_find_default_sdks() -> Result<(), Error> {
        if let Ok(developer_dir) = default_developer_directory() {
            assert!(!UnparsedSdk::find_developer_sdks(&developer_dir)?.is_empty());
            assert!(!UnparsedSdk::find_default_developer_sdks()?.is_empty());
        }

        Ok(())
    }

    #[test]
    fn test_find_command_line_tools_sdks() -> Result<(), Error> {
        let sdk_path = PathBuf::from(COMMAND_LINE_TOOLS_DEFAULT_PATH).join("SDKs");

        let res = UnparsedSdk::find_command_line_tools_sdks()?;

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
        for path in crate::find_system_xcode_developer_directories()? {
            UnparsedSdk::find_developer_sdks(&path)?;
        }

        Ok(())
    }
}
