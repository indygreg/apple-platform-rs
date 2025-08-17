// Copyright 2022 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use {
    crate::{AppleSdk, Error, Platform, SdkPath, SdkVersion},
    std::path::{Path, PathBuf},
};

#[cfg(feature = "parse")]
use crate::parsed_sdk::ParsedSdk;

/// A directory purported to hold an Apple SDK.
#[derive(Clone, Debug)]
pub struct SimpleSdk {
    /// Root directory of the SDK.
    path: PathBuf,

    /// Whether the root directory is a symlink to another path.
    is_symlink: bool,

    sdk_path: SdkPath,
}

impl AsRef<Path> for SimpleSdk {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AppleSdk for SimpleSdk {
    fn from_directory(path: &Path) -> Result<Self, Error> {
        let sdk = SdkPath::from_path(path)?;

        // Need to call symlink_metadata so symlinks aren't followed.
        let metadata = std::fs::symlink_metadata(path)?;

        let is_symlink = metadata.file_type().is_symlink();

        let json_path = path.join("SDKSettings.json");
        let plist_path = path.join("SDKSettings.plist");

        if json_path.exists() || plist_path.exists() {
            Ok(Self {
                path: path.to_path_buf(),
                is_symlink,
                sdk_path: sdk,
            })
        } else {
            Err(Error::PathNotSdk(path.to_path_buf()))
        }
    }

    fn is_symlink(&self) -> bool {
        self.is_symlink
    }

    fn platform(&self) -> &Platform {
        &self.sdk_path.platform
    }

    fn version(&self) -> Option<&SdkVersion> {
        self.sdk_path.version.as_ref()
    }

    fn supports_deployment_target(
        &self,
        _target_name: &str,
        _target_version: &SdkVersion,
    ) -> Result<bool, Error> {
        Err(Error::FunctionalityNotSupported(
            "evaluating deployment target support on UnparsedSdk instances",
        ))
    }
}

impl SimpleSdk {
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
        crate::{DeveloperDirectory, COMMAND_LINE_TOOLS_DEFAULT_PATH},
    };

    #[test]
    fn find_default_sdks() -> Result<(), Error> {
        if let Ok(developer_dir) = DeveloperDirectory::find_default_required() {
            assert!(!developer_dir.sdks::<SimpleSdk>()?.is_empty());
        }

        Ok(())
    }

    #[test]
    fn find_command_line_tools_sdks() -> Result<(), Error> {
        let sdk_path = PathBuf::from(COMMAND_LINE_TOOLS_DEFAULT_PATH).join("SDKs");

        let res = SimpleSdk::find_command_line_tools_sdks()?;

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
            for sdk in dir.sdks::<SimpleSdk>()? {
                if let Platform::Unknown(name) = sdk.platform() {
                    panic!("unknown platform: {}:{}", name, sdk.path.display());
                }
            }
        }

        Ok(())
    }
}
