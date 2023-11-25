// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Object maps.

use crate::block::Block;
use crate::btree::BTree;
use crate::{block::BlockReader, error::Result};
use apfs_types::common::{TransactionIdentifierRaw, VirtualObjectIdentifierRaw};
pub use apfs_types::object_map::*;
use apfs_types::{DiskStruct, ParsedDiskStruct};
use log::debug;
use std::cell::RefCell;

/// Describes common behavior of an object map.
pub trait ObjectMap {
    /// Walk entries in this mapping.
    fn walk(
        &self,
        reader: &impl BlockReader,
        cb: impl Fn(ObjectMapKeyParsed, ObjectMapValueParsed) -> Result<()>,
    ) -> Result<()>;

    /// Walk entries for a given virtual object ID.
    ///
    /// The supplied callback will be called for every entry for the provided
    /// ID.
    fn walk_oid(
        &self,
        reader: &impl BlockReader,
        oid: VirtualObjectIdentifierRaw,
        cb: impl Fn(ObjectMapKeyParsed, ObjectMapValueParsed) -> Result<()>,
    ) -> Result<()> {
        self.walk(
            reader,
            |k, v| if k.oid() == oid { cb(k, v) } else { Ok(()) },
        )
    }

    /// Find the latest key-value pair for a given object identifier.
    ///
    /// The maximum allowed transaction identifier filters out too-new candidates.
    fn find_latest_oid(
        &self,
        reader: &impl BlockReader,
        oid: VirtualObjectIdentifierRaw,
        xid: TransactionIdentifierRaw,
    ) -> Result<Option<(ObjectMapKeyParsed, ObjectMapValueParsed)>> {
        let newest_xid = RefCell::new(TransactionIdentifierRaw::new_zeroed());
        let newest_entry = RefCell::new(None);

        self.walk_oid(reader, oid, |k, v| {
            let mut newest_xid = newest_xid.borrow_mut();
            let mut newest_entry = newest_entry.borrow_mut();

            if k.xid() <= xid && k.xid() > *newest_xid {
                *newest_xid = k.xid();
                newest_entry.replace((k, v));
            }

            Ok(())
        })?;

        Ok(newest_entry.take())
    }
}

/// Represents an empty object map.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyObjectMap {}

impl ObjectMap for EmptyObjectMap {
    fn walk(
        &self,
        _reader: &impl BlockReader,
        _cb: impl Fn(ObjectMapKeyParsed, ObjectMapValueParsed) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }
}

/// Higher level interface for an object map.
pub struct ObjectMapBlock {
    om: ObjectMapBlockParsed,
    btree: BTree,
}

impl ObjectMapBlock {
    /// Construct an instance from a read block and a block reader.
    pub fn new(reader: &impl BlockReader, block: Block) -> Result<Self> {
        debug!("block {} -> object map", block.number());
        let om = ObjectMapBlockParsed::from_bytes(block.bytes())?;
        debug!("object map tree block: {:?}", om.tree_oid());
        let btree = BTree::from_block(reader.get_block_validated(om.tree_oid())?)?;

        Ok(Self { om, btree })
    }

    /// Obtain the object map header.
    pub fn header(&self) -> &ObjectMapBlockRaw {
        &self.om
    }

    /// Obtain a reference to the b-tree backing this object map.
    pub fn btree(&self) -> &BTree {
        &self.btree
    }
}

impl ObjectMap for ObjectMapBlock {
    /// Walk entries in the object map.
    ///
    /// This is a convenience method for walking the b-tree and coercing keys
    /// and values to the appropriate type.
    fn walk(
        &self,
        reader: &impl BlockReader,
        cb: impl Fn(ObjectMapKeyParsed, ObjectMapValueParsed) -> Result<()>,
    ) -> Result<()> {
        for res in self.btree.iter_entries(reader, &EmptyObjectMap::default()) {
            let (k, v) = res?;
            let k = ObjectMapKeyParsed::from_bytes(k.into())?;
            let v = ObjectMapValueParsed::from_bytes(v.into())?;

            cb(k, v)?;
        }

        Ok(())
    }
}
