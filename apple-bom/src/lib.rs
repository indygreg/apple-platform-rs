// Copyright 2022 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Interact with Apple BOM files.
//!
//! Apple Bill of Materials (BOM) files are a file format / data structure
//! for indexing file content with additional metadata. They are commonly
//! found in flat packages (e.g. `.pkg` files).
//!
//! This crate provides an interface for reading and writing Apple BOM
//! files.
//!
//! The gateway to reading support is [ParsedBom], which provides a read-only
//! interface to a BOM data structure.
//!
//! Writing support is still a work in progress.

pub mod format;
pub use format::ParsedBom;

use {
    chrono::{DateTime, TimeZone, Utc},
    simple_file_manifest::{
        S_IFDIR, S_IRGRP, S_IROTH, S_IRUSR, S_IWGRP, S_IWOTH, S_IWUSR, S_IXGRP, S_IXOTH, S_IXUSR,
    },
    std::{collections::BTreeMap, io::Read, path::Path},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("(de)serialization error: {0}")]
    Scroll(#[from] scroll::Error),

    #[error("unable to parse variable name as UTF-8")]
    BadVariableString,

    #[error("bad index into BOM data")]
    BadIndex,

    #[error("data type {0} not found")]
    NoVar(String),

    #[error("illegal BOM path \"{0}\": {1}")]
    BadPath(String, &'static str),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// The type of path in a BOM.
#[derive(Clone, Copy, Debug)]
pub enum BomPathType {
    /// A regular file.
    File,

    /// A directory.
    Directory,

    /// A symlink.
    Link,

    /// A device.
    Dev,

    /// Some other type we don't know about.
    Other(u8),
}

impl From<u8> for BomPathType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::File,
            2 => Self::Directory,
            3 => Self::Link,
            4 => Self::Dev,
            _ => Self::Other(v),
        }
    }
}

impl From<BomPathType> for u8 {
    fn from(t: BomPathType) -> Self {
        match t {
            BomPathType::File => 1,
            BomPathType::Directory => 2,
            BomPathType::Link => 3,
            BomPathType::Dev => 4,
            BomPathType::Other(v) => v,
        }
    }
}

/// Represents a full path in a BOM.
///
/// This is a higher-level data structure with a Rust friendly API. It has
/// fields for all the data constituting a path in a BOM.
#[derive(Clone, Debug)]
pub struct BomPath {
    /// The type of path.
    path_type: BomPathType,

    /// The full path.
    path: String,

    file_mode: u16,
    user_id: u32,
    group_id: u32,
    mtime: DateTime<Utc>,
    size: usize,
    crc32: Option<u32>,
    link_name: Option<String>,
}

impl BomPath {
    /// Construct an instance from a low-level BOM record.
    pub fn from_record(
        path: String,
        record: &crate::format::BomBlockPathRecord,
    ) -> Result<Self, Error> {
        let mtime = Utc.timestamp(record.mtime as _, 0);

        let path_type = BomPathType::from(record.path_type);

        let crc32 = match path_type {
            BomPathType::File | BomPathType::Link => Some(record.checksum_or_type),
            BomPathType::Directory | BomPathType::Dev | BomPathType::Other(_) => None,
        };

        Ok(Self {
            path_type,
            path,
            file_mode: record.mode,
            user_id: record.user,
            group_id: record.group,
            mtime,
            size: record.size as _,
            crc32,
            link_name: record.string_link_name(),
        })
    }

    /// The type of this path.
    pub fn path_type(&self) -> BomPathType {
        self.path_type
    }

    /// The full path of this instance.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// File mode bitfield.
    pub fn file_mode(&self) -> u16 {
        self.file_mode
    }

    /// Set the file mode to an explicit value.
    pub fn set_file_mode(&mut self, mode: u16) -> u16 {
        let old = self.file_mode;
        self.file_mode = mode;
        old
    }

    /// Obtain the symbolic file mode for this path.
    ///
    /// e.g. a string like `drwxr-xr-x`.
    pub fn symbolic_mode(&self) -> String {
        let mut mode = String::with_capacity(10);

        mode.push(match self.path_type {
            BomPathType::Directory => 'd',
            BomPathType::File => '-',
            BomPathType::Link => 'l',
            BomPathType::Dev => '?',
            BomPathType::Other(_) => '?',
        });

        mode.push(if self.file_mode as u32 & S_IRUSR != 0 {
            'r'
        } else {
            '-'
        });
        mode.push(if self.file_mode as u32 & S_IWUSR != 0 {
            'w'
        } else {
            '-'
        });
        mode.push(if self.file_mode as u32 & S_IXUSR != 0 {
            'x'
        } else {
            '-'
        });
        mode.push(if self.file_mode as u32 & S_IRGRP != 0 {
            'r'
        } else {
            '-'
        });
        mode.push(if self.file_mode as u32 & S_IWGRP != 0 {
            'w'
        } else {
            '-'
        });
        mode.push(if self.file_mode as u32 & S_IXGRP != 0 {
            'x'
        } else {
            '-'
        });
        mode.push(if self.file_mode as u32 & S_IROTH != 0 {
            'r'
        } else {
            '-'
        });
        mode.push(if self.file_mode as u32 & S_IWOTH != 0 {
            'w'
        } else {
            '-'
        });
        mode.push(if self.file_mode as u32 & S_IXOTH != 0 {
            'x'
        } else {
            '-'
        });

        mode
    }

    /// Numeric user identifier (UID) that owns this path.
    pub fn user_id(&self) -> u32 {
        self.user_id
    }

    /// Set the user identifier (UID) that owns this path.
    pub fn set_user_id(&mut self, uid: u32) -> u32 {
        let old = self.user_id;
        self.user_id = uid;
        old
    }

    /// Numeric group identifier (GID) that owns this path.
    pub fn group_id(&self) -> u32 {
        self.group_id
    }

    /// Set the group identifier (GID) that owns this path.
    pub fn set_group_id(&mut self, gid: u32) -> u32 {
        let old = self.user_id;
        self.group_id = gid;
        old
    }

    /// Modified time of this path.
    pub fn modified_time(&self) -> &DateTime<Utc> {
        &self.mtime
    }

    /// Set the modified time of this path.
    pub fn set_modified_time(&mut self, mtime: DateTime<Utc>) -> DateTime<Utc> {
        let old = self.mtime;
        self.mtime = mtime;
        old
    }

    /// Size of path in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Set the size of this path.
    pub fn set_size(&mut self, size: usize) -> usize {
        let old = self.size;
        self.size = size;
        old
    }

    /// CRC32 of this path.
    ///
    /// Should only be set for files and links.
    pub fn crc32(&self) -> Option<u32> {
        self.crc32
    }

    /// Set the CRC32 of this path.
    pub fn set_crc32(&mut self, value: Option<u32>) -> Option<u32> {
        let old = self.crc32;
        self.crc32 = value;
        old
    }

    /// The path that this link refers to.
    pub fn link_name(&self) -> Option<&str> {
        self.link_name.as_deref()
    }

    /// Set the link name for this path.
    pub fn set_link_name(&mut self, value: Option<String>) -> Option<String> {
        let old = self.link_name.clone();
        self.link_name = value;
        old
    }
}

fn validate_bom_path(s: &str) -> Result<(), Error> {
    if s.starts_with('.') {
        Err(Error::BadPath(s.to_string(), "path cannot start with ."))
    } else if s.starts_with('/') {
        Err(Error::BadPath(s.to_string(), "path cannot start with /"))
    } else if s.contains('\\') {
        Err(Error::BadPath(s.to_string(), "path cannot contain \\"))
    } else {
        Ok(())
    }
}

fn crc32_path(path: &Path) -> std::io::Result<(u32, usize)> {
    let mut h = crc32fast::Hasher::new();

    let mut fh = std::fs::File::open(path)?;
    let mut buffer = [0u8; 32768];
    let mut file_size = 0;

    loop {
        let bytes_read = fh.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        file_size += bytes_read;
        h.update(&buffer[0..bytes_read]);
    }

    Ok((h.finalize(), file_size))
}

fn crc32_data(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

/// Entity for constructing new BOM data structures.
#[derive(Clone, Debug)]
pub struct BomBuilder {
    /// Paths to materialize.
    ///
    /// Directories are not tracked explicitly. Rather they are derived
    /// at BOM generation time.
    paths: BTreeMap<String, BomPath>,

    default_mtime: DateTime<Utc>,

    default_uid: u32,
    default_gid: u32,

    default_mode_file: u16,
    default_mode_dir: u16,
}

impl Default for BomBuilder {
    fn default() -> Self {
        Self {
            paths: Default::default(),
            default_mtime: Utc::now(),
            default_uid: 0,
            default_gid: 0,
            // -rw-r--r--
            default_mode_file: (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) as u16,
            // drwxr-xr-x
            default_mode_dir: (S_IFDIR
                | S_IRUSR
                | S_IWUSR
                | S_IXUSR
                | S_IRGRP
                | S_IXGRP
                | S_IROTH
                | S_IXGRP) as u16,
        }
    }
}

impl BomBuilder {
    fn default_file_path(&self) -> BomPath {
        BomPath {
            path_type: BomPathType::File,
            path: "".to_string(),
            file_mode: self.default_mode_file,
            user_id: self.default_uid,
            group_id: self.default_gid,
            mtime: self.default_mtime,
            size: 0,
            crc32: None,
            link_name: None,
        }
    }

    /// Set the default file mode to use for files.
    pub fn default_mode_file(&mut self, mode: u16) {
        self.default_mode_file = mode;
    }

    /// Set the default file mode to use for directories.
    pub fn default_mode_directory(&mut self, mode: u16) {
        self.default_mode_dir = mode;
    }

    /// Set the default user ID (UID).
    pub fn default_user_id(&mut self, uid: u32) {
        self.default_uid = uid;
    }

    /// Set the default group ID (GID).
    pub fn default_group_id(&mut self, gid: u32) {
        self.default_gid = gid;
    }

    /// Set the default modified time.
    pub fn default_mtime(&mut self, mtime: DateTime<Utc>) {
        self.default_mtime = mtime;
    }

    /// Add a file to this BOM with file content derived from a filesystem path.
    ///
    /// A mutable reference to the just-added entry is returned to allow
    /// for further customization.
    pub fn add_file_from_path(
        &mut self,
        bom_path: impl ToString,
        path: impl AsRef<Path>,
    ) -> Result<&mut BomPath, Error> {
        let bom_path = bom_path.to_string();
        validate_bom_path(&bom_path)?;
        let path = path.as_ref();

        let (crc32, file_size) = crc32_path(path)?;

        let mut path = self.default_file_path();
        path.path = bom_path.clone();
        path.size = file_size;
        path.crc32 = Some(crc32);

        self.paths.insert(bom_path.clone(), path);

        Ok(self.paths.get_mut(&bom_path).unwrap())
    }

    /// Add a file to this BOM with content specified from a slice.
    ///
    /// A mutable reference to the just-added entry is returned to allow
    /// for further customization.
    pub fn add_file_from_data(
        &mut self,
        bom_path: impl ToString,
        data: impl AsRef<[u8]>,
    ) -> Result<&mut BomPath, Error> {
        let bom_path = bom_path.to_string();
        validate_bom_path(&bom_path)?;

        let data = data.as_ref();

        let mut path = self.default_file_path();
        path.path = bom_path.clone();
        path.size = data.len();
        path.crc32 = Some(crc32_data(data));

        self.paths.insert(bom_path.clone(), path);

        Ok(self.paths.get_mut(&bom_path).unwrap())
    }
}
