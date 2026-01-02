// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `PkgInfo` XML files.

use {
    crate::{distribution::Bundle, PkgResult},
    serde::{Deserialize, Serialize},
    std::io::Read,
};

/// Provides information about the package to install.
///
/// This includes authentication requirements, behavior after installation, etc.
/// See the fields for more descriptions.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PackageInfo {
    /// Authentication requirements for the package install.
    ///
    /// Values include `none` and `root`.
    #[serde(rename = "@auth")]
    pub auth: String,

    #[serde(rename = "@deleteObsoleteLanguages")]
    pub delete_obsolete_languages: Option<bool>,

    /// Whether symlinks found at install time should be resolved instead of being replaced by a
    /// real file or directory.
    #[serde(rename = "@followSymLinks")]
    pub follow_symlinks: Option<bool>,

    /// Format version of the package.
    ///
    /// Value is likely `2`.
    #[serde(rename = "@format-version")]
    pub format_version: u8,

    /// Identifies the tool that assembled this package.
    #[serde(rename = "@generator-version")]
    pub generator_version: Option<String>,

    /// Uniform type identifier that defines the package.
    ///
    /// Should ideally be unique to this package.
    #[serde(rename = "@identifier")]
    pub identifier: String,

    /// Default location where the payload hierarchy should be installed.
    #[serde(rename = "@install-location")]
    pub install_location: Option<String>,

    /// Defines minimum OS version on which the package can be installed.
    #[serde(rename = "@minimumSystemVersion")]
    pub minimum_system_version: Option<bool>,

    /// Defines if permissions of existing directories should be updated with ones from the payload.
    #[serde(rename = "@overwrite-permissions")]
    pub overwrite_permissions: Option<bool>,

    /// Action to perform after install.
    ///
    /// Potential values can include `logout`, `restart`, and `shutdown`.
    #[serde(rename = "@postinstall-action")]
    pub postinstall_action: Option<String>,

    /// Preserve extended attributes on files.
    #[serde(rename = "@preserve-xattr")]
    pub preserve_xattr: Option<bool>,

    /// Unknown.
    ///
    /// Probably has something to do with whether the installation tree can be relocated
    /// without issue.
    #[serde(rename = "@relocatable")]
    pub relocatable: Option<bool>,

    /// Whether items in the package should be compressed after installation.
    #[serde(rename = "@useHFSPlusCompression")]
    pub use_hfs_plus_compression: Option<bool>,

    /// Version of the package.
    ///
    /// This is the version of the package itself, not the version of the application
    /// being installed.
    #[serde(rename = "@version")]
    pub version: String,

    // End of attributes. Beginning of elements.
    #[serde(default)]
    pub atomic_update_bundle: Vec<BundleRef>,

    /// Versioning information about bundles within the payload.
    #[serde(default)]
    pub bundle: Vec<Bundle>,

    #[serde(default)]
    pub bundle_version: Vec<BundleRef>,

    /// Files to not obsolete during install.
    #[serde(default)]
    pub dont_obsolete: Vec<File>,

    /// Installs to process at next startup.
    #[serde(default)]
    pub install_at_startup: Vec<File>,

    /// Files to be patched.
    #[serde(default)]
    pub patch: Vec<File>,

    /// Provides information on the content being installed.
    pub payload: Option<Payload>,

    #[serde(default)]
    pub relocate: Vec<BundleRef>,

    /// Scripts to run before and after install.
    #[serde(default)]
    pub scripts: Scripts,

    #[serde(default)]
    pub strict_identifiers: Vec<BundleRef>,

    #[serde(default)]
    pub update_bundle: Vec<BundleRef>,

    #[serde(default)]
    pub upgrade_bundle: Vec<BundleRef>,
}

impl Default for PackageInfo {
    fn default() -> Self {
        Self {
            auth: "none".into(),
            delete_obsolete_languages: None,
            follow_symlinks: None,
            format_version: 2,
            generator_version: Some("rust-apple-flat-package".to_string()),
            identifier: "".to_string(),
            install_location: None,
            minimum_system_version: None,
            overwrite_permissions: None,
            postinstall_action: None,
            preserve_xattr: None,
            relocatable: None,
            use_hfs_plus_compression: None,
            version: "0".to_string(),
            atomic_update_bundle: vec![],
            bundle: vec![],
            bundle_version: vec![],
            dont_obsolete: vec![],
            install_at_startup: vec![],
            patch: vec![],
            payload: None,
            relocate: vec![],
            scripts: Default::default(),
            strict_identifiers: vec![],
            update_bundle: vec![],
            upgrade_bundle: vec![],
        }
    }
}

impl PackageInfo {
    /// Parse Distribution XML from a reader.
    pub fn from_reader(reader: impl Read) -> PkgResult<Self> {
        let mut de = serde_xml_rs::Deserializer::new_from_reader(reader);

        Ok(Self::deserialize(&mut de)?)
    }

    /// Parse Distribution XML from a string.
    pub fn from_xml(s: &str) -> PkgResult<Self> {
        let mut de = serde_xml_rs::Deserializer::from_config(
            serde_xml_rs::SerdeXml::default().overlapping_sequences(true),
            s.as_bytes(),
        );

        Ok(Self::deserialize(&mut de)?)
    }
}

/// File record.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct File {
    /// File path.
    #[serde(rename = "@path")]
    pub path: String,

    /// Required SHA-1 of file.
    #[serde(rename = "@required-sha1")]
    pub required_sha1: Option<String>,

    /// SHA-1 of file.
    #[serde(rename = "@sha1")]
    pub sha1: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Payload {
    #[serde(rename = "@numberOfFiles")]
    pub number_of_files: u64,
    #[serde(rename = "@installKBytes")]
    pub install_kbytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BundleRef {
    #[serde(rename = "@id")]
    pub id: Option<String>,
}

/// Wrapper type to represent <scripts>.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct Scripts {
    #[serde(rename = "#content")]
    pub scripts: Vec<Script>,
}

/// An entry in <scripts>.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum Script {
    #[serde(rename = "preinstall")]
    PreInstall(PreInstall),

    #[serde(rename = "postinstall")]
    PostInstall(PostInstall),
}

/// A script to run before install.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PreInstall {
    /// Name of script to run.
    #[serde(rename = "@file")]
    pub file: String,

    /// ID of bundle element to run before.
    #[serde(rename = "@component-id")]
    pub component_id: Option<String>,
}

/// A script to run after install.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PostInstall {
    /// Name of script to run.
    #[serde(rename = "@file")]
    pub file: String,

    /// ID of bundle element to run after.
    #[serde(rename = "@component-id")]
    pub component_id: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn scripts_decode() {
        const INPUT: &str = r#"
            <?xml version="1.0" encoding="utf-8"?>
            <pkg-info overwrite-permissions="true" relocatable="false" identifier="my-app" postinstall-action="none" version="1" format-version="2" generator-version="InstallCmds-807 (21D62)" install-location="/usr/bin/my-app" auth="root">
                <payload numberOfFiles="123" installKBytes="123"/>
                <bundle-version/>
                <upgrade-bundle/>
                <update-bundle/>
                <atomic-update-bundle/>
                <strict-identifier/>
                <relocate/>
                <scripts>
                    <preinstall file="./preinstall"/>
                    <postinstall file="./postinstall"/>
                </scripts>
            </pkg-info>
        "#;

        let info = PackageInfo::from_xml(INPUT.trim()).unwrap();

        assert_eq!(
            info.scripts.scripts,
            vec![
                Script::PreInstall(PreInstall {
                    file: "./preinstall".into(),
                    component_id: None,
                }),
                Script::PostInstall(PostInstall {
                    file: "./postinstall".into(),
                    component_id: None,
                })
            ]
        );
    }
}
