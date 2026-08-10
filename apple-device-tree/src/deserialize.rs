use alloc::{string::ToString, vec::Vec};
use scroll::{
    ctx::{self, StrCtx, TryFromCtx},
    Endian, Pread,
};

use crate::{DeviceTreeNode, DeviceTreeNodeProperty, PROP_NAME_LENGTH};

impl<'a> ctx::TryFromCtx<'a, Endian> for DeviceTreeNodeProperty {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let name = src.gread_with::<&str>(offset, StrCtx::Length(PROP_NAME_LENGTH))?;
        let length_with_flag: u32 = src.gread_with(offset, ctx)?;
        let is_placeholder = (length_with_flag & (1 << 31)) != 0;
        let length = length_with_flag & 0x7fffffff;
        let aligned_length = (length + 3) & !3;
        let mut value = Vec::new();
        for _ in 0..aligned_length {
            value.push(src.gread_with(offset, ctx)?);
        }

        Ok((
            DeviceTreeNodeProperty {
                name: name.trim_end_matches('\0').to_string(),
                length,
                value,
                is_placeholder,
            },
            *offset,
        ))
    }
}

impl<'a> ctx::TryFromCtx<'a, Endian> for DeviceTreeNode {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let n_properties: u32 = src.gread_with(offset, ctx)?;
        let n_children: u32 = src.gread_with(offset, ctx)?;

        let mut properties = Vec::new();
        for _ in 0..n_properties {
            let prop: DeviceTreeNodeProperty = src.gread_with(offset, ctx)?;
            properties.push(prop);
        }

        let mut children = Vec::new();
        for _ in 0..n_children {
            let child: DeviceTreeNode = src.gread_with(offset, ctx)?;
            children.push(child);
        }

        Ok((
            DeviceTreeNode {
                properties,
                children,
            },
            *offset,
        ))
    }
}

pub fn parse_device_tree(data: &[u8]) -> Result<DeviceTreeNode, scroll::Error> {
    DeviceTreeNode::try_from_ctx(data, Endian::Little).map(|(node, _)| node)
}
