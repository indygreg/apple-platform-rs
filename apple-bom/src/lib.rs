// Copyright 2022 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub mod format;

use chrono::{DateTime, TimeZone, Utc};

const S_IRUSR: u16 = 0o400;
const S_IWUSR: u16 = 0o200;
const S_IXUSR: u16 = 0o100;
const S_IRGRP: u16 = 0o040;
const S_IWGRP: u16 = 0o020;
const S_IXGRP: u16 = 0o010;
const S_IROTH: u16 = 0o004;
const S_IWOTH: u16 = 0o002;
const S_IXOTH: u16 = 0o001;

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

        mode.push(if self.file_mode & S_IRUSR != 0 {
            'r'
        } else {
            '-'
        });
        mode.push(if self.file_mode & S_IWUSR != 0 {
            'w'
        } else {
            '-'
        });
        mode.push(if self.file_mode & S_IXUSR != 0 {
            'x'
        } else {
            '-'
        });
        mode.push(if self.file_mode & S_IRGRP != 0 {
            'r'
        } else {
            '-'
        });
        mode.push(if self.file_mode & S_IWGRP != 0 {
            'w'
        } else {
            '-'
        });
        mode.push(if self.file_mode & S_IXGRP != 0 {
            'x'
        } else {
            '-'
        });
        mode.push(if self.file_mode & S_IROTH != 0 {
            'r'
        } else {
            '-'
        });
        mode.push(if self.file_mode & S_IWOTH != 0 {
            'w'
        } else {
            '-'
        });
        mode.push(if self.file_mode & S_IXOTH != 0 {
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

    /// Numeric group identifier (GID) that owns this path.
    pub fn group_id(&self) -> u32 {
        self.group_id
    }

    /// Modified time of this path.
    pub fn modified_time(&self) -> &DateTime<Utc> {
        &self.mtime
    }

    /// Size of path in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// CRC32 of this path.
    ///
    /// Should only be set for files and links.
    pub fn crc32(&self) -> Option<u32> {
        self.crc32
    }

    /// The path that this link refers to.
    pub fn link_name(&self) -> Option<&str> {
        self.link_name.as_deref()
    }
}
