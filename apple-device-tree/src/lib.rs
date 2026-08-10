#![no_std]

extern crate alloc;

pub mod deserialize;
pub mod serialize;

use alloc::string::String;
use alloc::vec::Vec;
use scroll::ctx::SizeWith;
use scroll::Endian;

pub const PROP_NAME_LENGTH: usize = 32;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(C)]
pub struct DeviceTreeNodeProperty {
    pub name: String,
    pub length: u32,
    pub value: Vec<u8>,
    pub is_placeholder: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(C)]
pub struct DeviceTreeNode {
    pub properties: Vec<DeviceTreeNodeProperty>,
    pub children: Vec<DeviceTreeNode>,
}

impl SizeWith<Endian> for DeviceTreeNode {
    fn size_with(_ctx: &Endian) -> usize {
        core::mem::size_of::<u32>()
    }
}

impl SizeWith<Endian> for DeviceTreeNodeProperty {
    fn size_with(_ctx: &Endian) -> usize {
        core::mem::size_of::<u32>() + core::mem::size_of::<u32>()
    }
}
