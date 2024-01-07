// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! APFS writing support.

use crate::container::ContainerSuperblockRaw;
use apfs_types::common::ObjectIdentifierRaw;
use apfs_types::container::{
    ContainerIncompatibileFeaturesRaw, CONTAINER_DEFAULT_BLOCK_SIZE_BYTES,
    CONTAINER_MAX_FILE_SYSTEMS, CONTAINER_SUPERBLOCK_MAGIC, MINIMUM_CONTAINER_SIZE_BYTES,
};
use apfs_types::object::{ObjectType, ObjectTypeFlags, ObjectTypeValueRaw};
use apfs_types::reaper::{ReaperBlockRaw, ReaperFlagsRaw};
use apfs_types::DiskStruct;
use uuid::Uuid;

pub mod block;
pub mod space_manager;

pub struct ContainerBuilder {
    pub block_size: u32,
    pub block_count: u64,
    pub uuid: Uuid,
}

impl Default for ContainerBuilder {
    fn default() -> Self {
        Self {
            block_size: CONTAINER_DEFAULT_BLOCK_SIZE_BYTES,
            block_count: MINIMUM_CONTAINER_SIZE_BYTES / CONTAINER_DEFAULT_BLOCK_SIZE_BYTES as u64,
            uuid: Uuid::new_v4(),
        }
    }
}

impl ContainerBuilder {
    pub fn make_superblock(&self) -> ContainerSuperblockRaw {
        let mut sb = ContainerSuperblockRaw::new_zeroed();

        {
            let o = sb.object_mut();
            o.set_identifier(1.into());
            o.set_transaction_identifier(1.into());
            o.set_typ(ObjectTypeValueRaw::from_type_and_flags(
                ObjectType::ContainerSuperblock,
                ObjectTypeFlags::Ephemeral,
            ));
            // Subtype isn't set.
        }

        sb.magic_mut().copy_from_slice(CONTAINER_SUPERBLOCK_MAGIC);
        sb.set_block_size_bytes(self.block_size);
        sb.set_block_count(self.block_count);

        sb.incompatible_features_mut()
            .insert(ContainerIncompatibileFeaturesRaw::Version2);

        sb.identifier_mut()
            .get_mut()
            .copy_from_slice(self.uuid.as_ref());

        sb.set_space_manager_oid(1024.into());
        sb.set_reaper_oid(1025.into());

        sb.volume_oids_mut()[0] = 1026.into();

        // Size of the container divided by 512 MiB rounded up no greater than
        // CONTAINER_MAX_FILE_SYSTEMS.
        sb.set_maximum_filesystems(std::cmp::min(
            (sb.block_size_bytes() as u64 * sb.block_count()).div_ceil(512 * 1048576) as u32,
            CONTAINER_MAX_FILE_SYSTEMS as u32,
        ));

        sb
    }

    fn make_reaper(&self, oid: ObjectIdentifierRaw) {
        let mut rb = ReaperBlockRaw::new_zeroed();

        {
            let o = rb.object_mut();
            o.set_identifier(oid);
            o.set_transaction_identifier(1.into());
            o.set_typ(ObjectTypeValueRaw::from_type_and_flags(
                ObjectType::Reaper,
                ObjectTypeFlags::Ephemeral,
            ));
        }

        rb.set_next_reap_id(1);
        rb.set_flags(ReaperFlagsRaw::BHM_FLAG);

        rb.set_state_buffer_size(self.block_size - core::mem::size_of::<ReaperBlockRaw>() as u32);
    }
}
