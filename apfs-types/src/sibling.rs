// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Siblings.
//!
//! Siblings are hard links that refer to the same inode. Each sibling
//! has its own identifier distinct from the inode's.
//!
//! The sibling with the lowest number is the "primary link."

use crate::{filesystem::FileSystemKeyRaw, DynamicSized};
use core::ops::Range;

#[cfg(feature = "derive")]
use {
    crate::{DynamicSizedParse, ParseError},
    apfs_derive::ApfsData,
};

/// Sibling link record key (`j_sibling_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct SiblingLinkRecordKeyRaw {
    /// Common filesystem object header.
    ///
    /// Identifier is inode number.
    pub header: FileSystemKeyRaw,

    /// The sibling's unique identifier.
    pub sibling_id: u64,
}

/// Sibling link record value (`j_sibling_val_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct SiblingLinkRecordValueRaw {
    /// Filesystem object identifier for the parent directory's inode.
    pub parent_id: u64,

    /// Length of the name in bytes, including trailing NULL.
    ///
    /// The use of a u64 is likely for padding reasons. Names should never
    /// be anywhere close to that long.
    ///
    /// Our [DynamicSized] implementation will panic if this value is
    /// larger than usize.
    pub name_length: u64,

    /// The name as a NULL terminated UTF-8 string.
    #[cfg_attr(feature = "derive", apfs(trailing_data = "crate::pod::ApfsString"))]
    pub name: [u8; 0],
}

impl DynamicSized for SiblingLinkRecordValueRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        if self.name_length > usize::MAX as u64 {
            panic!("invalid name length; cannot be larger than machine native integer");
        }

        0..self.name_length as usize
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for SiblingLinkRecordValueRaw {
    type TrailingData = crate::pod::ApfsString;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::ApfsString::from_bytes(data)
    }
}

/// A sibling map record key (`j_sibling_map_key_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_key))]
#[repr(C, packed)]
pub struct SiblingMapRecordKeyRaw {
    /// Common filesystem object header.
    ///
    /// Object ID is the sibling's unique identifier. Should match the
    /// `sibling_id` field on [SiblingLinkRecordKeyRaw].
    pub header: FileSystemKeyRaw,
}

/// A sibling map record value (`j_sibling_map_val_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData), apfs(filesystem_value))]
#[repr(C, packed)]
pub struct SiblingMapRecordValueRaw {
    /// The inode number of the underlying file.
    pub file_id: u64,
}
