// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Distribution XML file format.
//!
//! See https://developer.apple.com/library/archive/documentation/DeveloperTools/Reference/DistributionDefinitionRef/Chapters/Distribution_XML_Ref.html
//! for Apple's documentation of this file format.

use {
    crate::PkgResult,
    serde::{Deserialize, Serialize},
    std::io::Read,
};

/// Represents a distribution XML file.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename = "installer-gui-script", rename_all = "kebab-case")]
pub struct Distribution {
    #[serde(rename = "@minSpecVersion")]
    pub min_spec_version: u8,

    // maxSpecVersion and verifiedSpecVersion are reserved attributes but not yet defined.
    pub background: Option<Background>,
    pub choice: Vec<Choice>,
    pub choices_outline: ChoicesOutline,
    pub conclusion: Option<Conclusion>,
    pub domains: Option<Domains>,
    pub installation_check: Option<InstallationCheck>,
    pub license: Option<License>,
    #[serde(default)]
    pub locator: Vec<Locator>,
    pub options: Option<Options>,
    #[serde(default)]
    pub pkg_ref: Vec<PkgRef>,
    pub product: Option<Product>,
    pub readme: Option<Readme>,
    pub script: Option<Script>,
    pub title: Option<Title>,
    pub volume_check: Option<VolumeCheck>,
    pub welcome: Option<Welcome>,
}

impl Distribution {
    /// Parse Distribution XML from a reader.
    pub fn from_reader(reader: impl Read) -> PkgResult<Self> {
        let mut de = serde_xml_rs::Deserializer::from_config(
            serde_xml_rs::SerdeXml::default().overlapping_sequences(true),
            reader,
        );

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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AllowedOsVersions {
    #[serde(rename = "os-version")]
    os_versions: Vec<OsVersion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct App {
    #[serde(rename = "@id")]
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Background {
    // TODO convert to enum.
    #[serde(rename = "@alignment")]
    pub alignment: Option<String>,
    #[serde(rename = "@file")]
    pub file: String,
    #[serde(rename = "@mime-type")]
    pub mime_type: Option<String>,
    // TODO convert to enum
    #[serde(rename = "@scaling")]
    pub scaling: Option<String>,
    #[serde(rename = "@uti")]
    pub uti: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Bundle {
    #[serde(rename = "@CFBundleShortVersionString")]
    pub cf_bundle_short_version_string: Option<String>,
    #[serde(rename = "@CFBundleVersion")]
    pub cf_bundle_version: Option<String>,
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@path")]
    pub path: String,
    #[serde(rename = "@search")]
    pub search: Option<bool>,
    // BuildVersion, SourceVersion reserved attributes.
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BundleVersion {
    #[serde(default)]
    pub bundle: Vec<Bundle>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Choice {
    // The naming format on this element is all over the place.
    #[serde(rename = "@customLocation")]
    pub custom_location: Option<String>,
    #[serde(rename = "@customLocationAllowAlternateVolumes")]
    pub custom_location_allow_alternative_volumes: Option<bool>,
    #[serde(rename = "@description")]
    pub description: Option<String>,
    #[serde(rename = "@description-mime-type")]
    pub description_mime_type: Option<String>,
    #[serde(rename = "@enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@selected")]
    pub selected: Option<bool>,
    #[serde(rename = "@start_enabled")]
    pub start_enabled: Option<bool>,
    #[serde(rename = "@start_selected")]
    pub start_selected: Option<bool>,
    #[serde(rename = "@start_visible")]
    pub start_visible: Option<bool>,
    // Supposed to be required. But there are elements with only `id` attribute in wild.
    #[serde(rename = "@title")]
    pub title: Option<String>,
    #[serde(rename = "@visible")]
    pub visible: Option<bool>,
    // bundle, customLocationIsSelfContained, tooltip, and versStr are reserved attributes.
    #[serde(default, rename = "pkg-ref")]
    pub pkg_ref: Vec<PkgRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChoicesOutline {
    // ui is a reserved attribute.
    pub line: Vec<Line>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Conclusion {
    #[serde(rename = "@file")]
    pub file: String,
    #[serde(rename = "@mime-type")]
    pub mime_type: Option<String>,
    #[serde(rename = "@uti")]
    pub uti: Option<String>,
    // language is a reserved attribute.
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Domains {
    #[serde(rename = "@enable_anywhere")]
    pub enable_anywhere: bool,
    #[serde(rename = "@enable_currentUserHome")]
    pub enable_current_user_home: bool,
    #[serde(rename = "@enable_localSystem")]
    pub enable_local_system: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct InstallationCheck {
    #[serde(rename = "@script")]
    pub script: Option<bool>,
    pub ram: Option<Ram>,
    #[serde(rename = "required-graphics")]
    pub required_graphics: Option<RequiredGraphics>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct License {
    #[serde(rename = "@file")]
    pub file: String,
    #[serde(rename = "@mime-type")]
    pub mime_type: Option<String>,
    #[serde(rename = "@uti")]
    pub uti: Option<String>,
    // auto, language, and sla are reserved but not defined.
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Line {
    #[serde(rename = "@choice")]
    pub choice: String,
    #[serde(default, rename = "line")]
    pub lines: Vec<Line>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Locator {
    #[serde(rename = "search")]
    pub searches: Vec<Search>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct MustClose {
    pub app: Vec<App>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Options {
    #[serde(rename = "@allow-external-scripts")]
    pub allow_external_scripts: Option<bool>,
    #[serde(rename = "@customize")]
    pub customize: Option<String>,
    #[serde(rename = "@customLocation")]
    pub custom_location: Option<String>,
    #[serde(rename = "@customLocationAllowAlternateVolumes")]
    pub custom_location_allow_alternate_volumes: Option<String>,
    #[serde(rename = "@hostArchitectures")]
    pub host_architecutres: Option<String>,
    #[serde(rename = "@mpkg")]
    pub mpkg: Option<String>,
    #[serde(rename = "@require-scripts")]
    pub require_scripts: Option<bool>,
    #[serde(rename = "@rootVolumeOnly")]
    pub root_volume_only: Option<bool>,
    // type, visibleOnlyForPredicate are reserved attributes.
}

/// Defines a range of supported OS versions.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct OsVersion {
    #[serde(rename = "@before")]
    pub before: Option<String>,
    #[serde(rename = "@min")]
    pub min: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PkgRef {
    #[serde(rename = "@active")]
    pub active: Option<bool>,
    #[serde(rename = "@auth")]
    pub auth: Option<String>,
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@installKBytes")]
    pub install_kbytes: Option<u64>,
    // TODO make enum
    #[serde(rename = "@onConclusion")]
    pub on_conclusion: Option<String>,
    #[serde(rename = "@onConclusionScript")]
    pub on_conclusion_script: Option<String>,
    #[serde(rename = "@version")]
    pub version: Option<String>,
    // archiveKBytes, packageIdentifier reserved attributes.
    #[serde(rename = "must-close")]
    pub must_close: Option<MustClose>,
    #[serde(rename = "bundle-version")]
    pub bundle_version: Option<BundleVersion>,
    #[serde(default)]
    pub relocate: Vec<Relocate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Product {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@version")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Ram {
    #[serde(rename = "@min-gb")]
    pub min_gb: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Readme {
    #[serde(rename = "@file")]
    pub file: String,
    #[serde(rename = "@mime-type")]
    pub mime_type: Option<String>,
    #[serde(rename = "@uti")]
    pub uti: Option<String>,
    // language is reserved.
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Relocate {
    #[serde(rename = "@search-id")]
    pub search_id: String,
    pub bundle: Bundle,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RequiredBundles {
    #[serde(rename = "@all")]
    pub all: Option<bool>,
    #[serde(rename = "@description")]
    pub description: Option<String>,
    #[serde(rename = "bundle")]
    pub bundles: Vec<Bundle>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RequiredClDevice {
    #[serde(rename = "#content")]
    pub predicate: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RequiredGlRenderer {
    #[serde(rename = "#content")]
    pub predicate: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RequiredGraphics {
    #[serde(rename = "@description")]
    pub description: Option<String>,
    #[serde(rename = "@single-device")]
    pub single_device: Option<bool>,
    pub required_cl_device: Option<RequiredClDevice>,
    pub required_gl_renderer: Option<RequiredGlRenderer>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Script {
    // language is a reserved attribute.
    #[serde(rename = "#content")]
    pub script: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum SearchValue {
    #[serde(rename = "bundle")]
    Bundle(Bundle),
    #[serde(rename = "script")]
    Script(Script),
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Search {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@script")]
    pub script: Option<String>,
    #[serde(rename = "@search-id")]
    pub search_id: Option<String>,
    #[serde(rename = "@search-path")]
    pub search_path: Option<String>,
    #[serde(rename = "@type")]
    pub search_type: String,
    pub value: SearchValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Title {
    #[serde(rename = "#content")]
    pub title: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename = "kebab-case")]
pub struct VolumeCheck {
    #[serde(rename = "@script")]
    pub script: Option<bool>,
    pub allowed_os_versions: Option<AllowedOsVersions>,
    pub required_bundles: Option<RequiredBundles>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Welcome {
    #[serde(rename = "@file")]
    pub file: String,
    #[serde(rename = "@mime-type")]
    pub mime_type: Option<String>,
    #[serde(rename = "@uti")]
    pub uti: Option<String>,
    // language reserved attribute.
}
