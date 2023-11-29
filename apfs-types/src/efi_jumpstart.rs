// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! EFI Jumpstart

use crate::{common::PhysicalAddressRangeRaw, object::ObjectHeaderRaw, DynamicSized};
use core::ops::Range;

#[cfg(feature = "derive")]
use {
    crate::{DynamicSizedParse, ParseError},
    apfs_derive::ApfsData,
};

pub const EFI_JUMPSTART_MAGIC: &[u8; 4] = b"RDSJ";

pub const EFI_JUMPSTART_VERSION: u32 = 1;

/// Block holding information about the embedded EFI driver (`nx_efi_jumpstart_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct EfiJumpstartBlockRaw {
    /// Common object header (`nej_o`).
    pub object: ObjectHeaderRaw,

    /// Value to confirm reading of EFI jumpstart data (`nej_magic`).
    ///
    /// Value is always [EFI_JUMPSTART_MAGIC].
    pub magic: u32,

    /// The version of this data structure (`nej_version`).
    ///
    /// Value is always [EFI_JUMPSTART_VERSION].
    pub version: u32,

    /// Size in bytes of embedded EFI driver (`nej_efi_file_len`).
    pub efi_file_length: u32,

    /// The number of extents in this record (`nej_num_extents`).
    pub number_extents: u32,

    /// Reserved (`nej_reserved`).
    ///
    /// Populate with 0 and preserve value during modification.
    pub reserved: [u64; 16],

    /// Locations where the EFI driver is stored (`nej_rec_extents`).
    ///
    /// Array length defined by the [Self::number_extents] field.
    #[cfg_attr(
        feature = "derive",
        apfs(
            trailing_data = "crate::pod::MemoryBackedArray<PhysicalAddressRangeRaw, crate::common::PhysicalAddressRangeParsed>"
        )
    )]
    pub record_extents: [PhysicalAddressRangeRaw; 0],
}

impl DynamicSized for EfiJumpstartBlockRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        let size = self.number_extents as usize * core::mem::size_of::<PhysicalAddressRangeRaw>();

        0..size
    }
}

#[cfg(feature = "derive")]
impl DynamicSizedParse for EfiJumpstartBlockRaw {
    type TrailingData = crate::pod::MemoryBackedArray<
        PhysicalAddressRangeRaw,
        crate::common::PhysicalAddressRangeParsed,
    >;

    fn parse_trailing_data(&self, data: bytes::Bytes) -> Result<Self::TrailingData, ParseError> {
        crate::pod::MemoryBackedArray::new(data, self.number_extents as _)
    }
}
