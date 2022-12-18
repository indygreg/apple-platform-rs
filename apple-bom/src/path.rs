// Copyright 2022 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use {
    crate::error::Error,
    chrono::{DateTime, TimeZone, Utc},
    simple_file_manifest::{
        S_IRGRP, S_IROTH, S_IRUSR, S_IWGRP, S_IWOTH, S_IWUSR, S_IXGRP, S_IXOTH, S_IXUSR,
    },
    std::ffi::CString,
};

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
    pub(crate) path_type: BomPathType,

    /// The full path.
    pub(crate) path: String,

    pub(crate) file_mode: u16,
    pub(crate) user_id: u32,
    pub(crate) group_id: u32,
    pub(crate) mtime: DateTime<Utc>,
    pub(crate) size: usize,
    pub(crate) crc32: Option<u32>,
    pub(crate) link_name: Option<String>,
}

impl BomPath {
    /// Construct an instance from a low-level BOM record.
    pub fn from_record(
        path: String,
        record: &crate::format::BomBlockPathRecord,
    ) -> Result<Self, Error> {
        let mtime = Utc
            .timestamp_opt(record.mtime as _, 0)
            .single()
            .ok_or(Error::BadTime)?;

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

    /// The path that this link refers to, as a [CString].
    pub fn link_name_cstring(&self) -> Option<CString> {
        if let Some(link_name) = &self.link_name {
            let mut data = Vec::<u8>::with_capacity(link_name.as_bytes().len() + 1);
            data.extend(link_name.as_bytes());
            data.push(0);

            Some(CString::new(data).expect("should be valid C string"))
        } else {
            None
        }
    }

    /// Set the link name for this path.
    pub fn set_link_name(&mut self, value: Option<String>) -> Option<String> {
        let old = self.link_name.clone();
        self.link_name = value;
        old
    }
}
