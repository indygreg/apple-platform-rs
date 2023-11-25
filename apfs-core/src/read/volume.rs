// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::block::BlockReader;
use crate::btree::{BTree, NodeValue};
use crate::error::{ApfsError, Result};
use crate::object_map::{ObjectMap, ObjectMapBlock};
use crate::read::filesystem::FilesystemTreeReader;
use apfs_types::common::{ObjectIdentifierRaw, PhysicalObjectIdentifierRaw};
use apfs_types::data_stream::{PhysicalExtentRecordKeyParsed, PhysicalExtentRecordValueParsed};
use apfs_types::filesystem::FileSystemKeyParsed;
use apfs_types::object::{ObjectTypeValueRaw, StorageClass};
use apfs_types::snapshot::{SnapshotMetadataRecordKeyParsed, SnapshotMetadataRecordValueParsed};
pub use apfs_types::volume::*;
use apfs_types::ParsedDiskStruct;

/// A reader for a single APFS volume.
pub struct VolumeReader<'a, R: BlockReader> {
    reader: &'a R,
    superblock: VolumeSuperblockParsed,
    object_map: ObjectMapBlock,
}

impl<'a, R: BlockReader> VolumeReader<'a, R> {
    pub fn new(reader: &'a R, superblock: VolumeSuperblockParsed) -> Result<Self> {
        let om_block = reader.get_block_validated(superblock.object_map_oid())?;
        let object_map = ObjectMapBlock::new(reader, om_block)?;

        Ok(Self {
            reader,
            superblock,
            object_map,
        })
    }

    pub fn superblock(&self) -> &VolumeSuperblockParsed {
        &self.superblock
    }

    /// Resolve a generic OID and associated [ObjectTypeValueRaw] into a physical identifier.
    pub fn resolve_oid(
        &self,
        id: ObjectIdentifierRaw,
        info: ObjectTypeValueRaw,
    ) -> Result<PhysicalObjectIdentifierRaw> {
        match info.flags().storage_class() {
            StorageClass::Physical => Ok(id.into()),
            StorageClass::Ephemeral => {
                Err(ApfsError::Unimplemented("resolving ephemeral identifier"))
            }
            StorageClass::Virtual => Ok(self
                .object_map
                .find_latest_oid(
                    self.reader,
                    id.into(),
                    self.superblock.object().transaction_identifier(),
                )?
                .ok_or_else(|| ApfsError::VirtualObjectNotFound(id.into()))?
                .1
                .address()
                .into()),
        }
    }

    /// Resolve the root filesystem tree for this volume.
    pub fn root_tree(&self) -> Result<BTree> {
        let oid = self.resolve_oid(
            self.superblock.root_tree_oid(),
            self.superblock.root_tree_type(),
        )?;
        let block = self.reader.get_block_validated(oid)?;

        BTree::from_block(block)
    }

    /// Obtain a [FilesystemTreeReader] for this instance.
    pub fn filesystem_tree(&self) -> Result<FilesystemTreeReader<R, ObjectMapBlock>> {
        let tree = self.root_tree()?;

        Ok(FilesystemTreeReader::new(
            tree,
            self.reader,
            &self.object_map,
        ))
    }

    /// Walk the filesystem root tree.
    pub fn walk_root_tree(
        &self,
        cb: impl Fn(FileSystemKeyParsed, NodeValue) -> Result<()>,
    ) -> Result<()> {
        let root = self.root_tree()?;

        for res in root.iter_entries(self.reader, &self.object_map) {
            let (k, v) = res?;

            let k = FileSystemKeyParsed::from_bytes(k.into())?;

            cb(k, v)?;
        }

        Ok(())
    }

    pub fn extent_reference_tree(&self) -> Result<BTree> {
        let oid = self.resolve_oid(
            self.superblock.extent_reference_tree_oid(),
            self.superblock.extent_reference_tree_type(),
        )?;
        let block = self.reader.get_block_validated(oid)?;

        BTree::from_block(block)
    }

    pub fn iter_extent_reference_tree(
        &self,
    ) -> Result<
        impl Iterator<
                Item = Result<(
                    PhysicalExtentRecordKeyParsed,
                    PhysicalExtentRecordValueParsed,
                )>,
            > + '_,
    > {
        Ok(self
            .extent_reference_tree()?
            .iter_entries(self.reader, &self.object_map)
            .map(move |res| {
                let (k, v) = res?;

                let k = PhysicalExtentRecordKeyParsed::from_bytes(k.into())?;
                let v = PhysicalExtentRecordValueParsed::from_bytes(v.into())?;

                Ok((k, v))
            }))
    }

    pub fn snapshot_metadata_tree(&self) -> Result<BTree> {
        let oid = self.resolve_oid(
            self.superblock.snapshot_metadata_tree_oid(),
            self.superblock.snapshot_metadata_tree_type(),
        )?;
        let block = self.reader.get_block_validated(oid)?;

        BTree::from_block(block)
    }

    pub fn iter_snapshot_metadata_tree(
        &self,
    ) -> Result<
        impl Iterator<
                Item = Result<(
                    SnapshotMetadataRecordKeyParsed,
                    SnapshotMetadataRecordValueParsed,
                )>,
            > + '_,
    > {
        Ok(self
            .snapshot_metadata_tree()?
            .iter_entries(self.reader, &self.object_map)
            .map(|res| {
                let (k, v) = res?;
                let k = SnapshotMetadataRecordKeyParsed::from_bytes(k.into())?;
                let v = SnapshotMetadataRecordValueParsed::from_bytes(v.into())?;

                Ok((k, v))
            }))
    }
}
