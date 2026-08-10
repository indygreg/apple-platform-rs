use core::str;

use crate::{DeviceTreeNode, DeviceTreeNodeProperty, PROP_NAME_LENGTH};
use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use scroll::{
    ctx::{self},
    Endian, Pread, Pwrite,
};

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "variant", content = "value"))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PropertyValue {
    Empty,
    StringArray(Vec<String>),
    String(String),
    Placeholder(String),
    Number(u64),
    Bytes(Vec<u8>),
}

fn value_for_property(property: &DeviceTreeNodeProperty) -> (String, PropertyValue) {
    if property.length == 0 {
        return (property.length.to_string(), PropertyValue::Empty);
    }

    let (str_arr, is_str) = strings_from_property(property);
    if is_str && !str_arr.is_empty() && str_arr[0].len() != 1 {
        if str_arr.len() != 1 {
            return (
                property.length.to_string(),
                PropertyValue::StringArray(str_arr),
            );
        }
        if property.is_placeholder {
            return (
                property.length.to_string(),
                PropertyValue::Placeholder(str_arr[0].clone()),
            );
        } else {
            return (
                property.length.to_string(),
                PropertyValue::String(str_arr[0].clone()),
            );
        }
    }

    if property.length == 4 {
        let value: u32 = property.value.pread_with(0, Endian::Little).unwrap_or(0);
        return (
            property.length.to_string(),
            PropertyValue::Number(value as u64),
        );
    }

    if property.length == 8 {
        let value: u64 = property.value.pread_with(0, Endian::Little).unwrap_or(0);
        return (property.length.to_string(), PropertyValue::Number(value));
    }

    (
        property.length.to_string(),
        PropertyValue::Bytes(property.value.clone()),
    )
}

pub fn string_for_node(node: &DeviceTreeNode) -> BTreeMap<String, BTreeMap<String, PropertyValue>> {
    let mut properties = BTreeMap::new();
    let mut node_name = String::new();

    for property in &node.properties {
        let prop_name = property.name.trim_end_matches('\0');
        if prop_name == "name" {
            if let (_, PropertyValue::String(name)) = value_for_property(property) {
                node_name = name;
            }
        } else {
            let (_size, property_value) = value_for_property(property);
            properties.insert(prop_name.to_string(), property_value);
        }
    }

    if !node.children.is_empty() {
        let children: BTreeMap<String, BTreeMap<String, PropertyValue>> =
            node.children.iter().flat_map(string_for_node).collect();

        properties.insert(
            "children".to_string(),
            PropertyValue::StringArray(children.keys().cloned().collect()),
        );
    }

    BTreeMap::from([(node_name, properties)])
}

pub fn strings_from_property(property: &DeviceTreeNodeProperty) -> (Vec<String>, bool) {
    let mut str_arr = Vec::new();
    let mut curr_str = Vec::new();
    let mut is_str = true;

    for &c in &property.value {
        if (c != 0 && c < 0x20) || c >= 0x7f || property.name.trim_end_matches('\0') == "reg" {
            is_str = false;
            break;
        } else if c == 0 && !curr_str.is_empty() {
            if let Ok(s) = str::from_utf8(&curr_str) {
                str_arr.push(s.to_string());
            }
            curr_str.clear();
        } else if c != 0 {
            curr_str.push(c);
        }
    }

    (str_arr, is_str)
}

impl<'a> ctx::TryIntoCtx<Endian> for &'a DeviceTreeNodeProperty {
    type Error = scroll::Error;

    fn try_into_ctx(self, dst: &mut [u8], ctx: Endian) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        let mut name_bytes = [0u8; PROP_NAME_LENGTH];
        let name_slice = self.name.as_bytes();
        name_bytes[..name_slice.len().min(PROP_NAME_LENGTH)]
            .copy_from_slice(&name_slice[..name_slice.len().min(PROP_NAME_LENGTH)]);
        dst.gwrite_with(name_bytes, offset, ctx)?;

        let length_with_flag = self.length | if self.is_placeholder { 1 << 31 } else { 0 };
        dst.gwrite_with(length_with_flag, offset, ctx)?;

        let aligned_length = (self.length + 3) & !3;
        let mut padded_value = self.value.clone();
        padded_value.resize(aligned_length as usize, 0);
        dst.gwrite_with(padded_value.as_slice(), offset, ())?;

        Ok(*offset)
    }
}

impl<'a> ctx::TryIntoCtx<Endian> for &'a DeviceTreeNode {
    type Error = scroll::Error;

    fn try_into_ctx(self, dst: &mut [u8], ctx: Endian) -> Result<usize, Self::Error> {
        let mut offset = 0;

        dst.gwrite_with(self.properties.len() as u32, &mut offset, ctx)?;
        dst.gwrite_with(self.children.len() as u32, &mut offset, ctx)?;

        for prop in &self.properties {
            offset += prop.try_into_ctx(&mut dst[offset..], ctx)?;
        }

        // Write children
        for child in &self.children {
            offset += child.try_into_ctx(&mut dst[offset..], ctx)?;
        }

        Ok(offset)
    }
}
