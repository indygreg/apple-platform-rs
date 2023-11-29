// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Reaper.
//!
//! The reaper facilitates deleting large objects over multiple transactions.
//!
//! There is a single reaper per container. The main reaper data structure
//! is [ReaperBlockRaw]. This structure contains pointers to other data structures.

use crate::{
    common::{ObjectIdentifierRaw, TransactionIdentifierRaw},
    object::ObjectHeaderRaw,
    object_map::ObjectMapKeyRaw,
    DynamicSized,
};
use bitflags::bitflags;
use core::ops::Range;

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

#[cfg(doc)]
use crate::{container::*, object_map::*, snapshot::*};

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct ReaperFlagsRaw: u32 {
        /// Reserved (`NR_BHM_FLAG`).
        ///
        /// Must always be set.
        const BHM_FLAG = 1;

        /// The current object is being reaped (`NR_CONTINUE`).
        const Continue = 2;

        const _ = !0;
    }
}

/// Reaper block (`nx_reaper_phys_t`).
///
/// There's a single instance of this struct/block per container. The
/// block containing the instance is pointed to by the
/// [ContainerSuperblockRaw::reaper_oid] field.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ReaperBlockRaw {
    /// Common block object header (`nr_o`).
    pub object: ObjectHeaderRaw,
    /// (`nr_next_reap_id`)
    pub next_reap_id: u64,
    /// (`nr_completed_id`)
    pub completed_id: u64,
    /// (`nr_head`)
    pub head: ObjectIdentifierRaw,
    /// (`nr_tail`)
    pub tail: ObjectIdentifierRaw,
    /// (`nr_flags`)
    pub flags: ReaperFlagsRaw,
    /// (`nr_rlcount`)
    pub rlcount: u32,
    /// (`nr_type`)
    pub typ: u32,
    /// (`nr_size`)
    pub size: u32,
    /// (`nr_fs_oid`)
    pub fs_oid: ObjectIdentifierRaw,
    /// (`nr_oid`)
    pub oid: ObjectIdentifierRaw,
    /// (`nr_xid`)
    pub xid: TransactionIdentifierRaw,
    /// (`nr_nrle_flags`)
    pub nrle_flags: u32,
    /// (`nr_state_buffer_size`)
    pub state_buffer_size: u32,
    /// (`nr_state_buffer`)
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub state_buffer: [u8; 0],
}

impl DynamicSized for ReaperBlockRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        0..self.state_buffer_size as usize
    }
}

bitflags! {
    /// Reaper list entry flags.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct ReaperListEntryFlagsRaw: u32 {
        /// (`NRLE_VALID`)
        const Valid = 0x01;
        /// (`NRLE_REAP_ID_RECORD`)
        const ReapIdRecord = 0x02;
        /// (`NRLE_CALL`)
        const Call = 0x04;
        /// (`NRLE_COMPLETION`)
        const Completion = 0x08;
        /// (`NRLE_CLEANUP`)
        const Cleanup = 0x10;

        const _ = !0;
    }
}

/// Reaper list entry (`nx_reap_list_entry_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ReapListEntryRaw {
    /// (`nrle_next`)
    pub next: u32,
    /// (`nrle_flags`)
    pub flags: ReaperListEntryFlagsRaw,
    /// (`nrle_type`)
    pub typ: u32,
    /// (`nrle_size`)
    pub size: u32,
    /// (`nrle_fs_oid`)
    pub fs_oid: ObjectIdentifierRaw,
    /// (`nrle_oid`)
    pub oid: ObjectIdentifierRaw,
    /// (`nrle_xid`)
    pub xid: TransactionIdentifierRaw,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    #[cfg_attr(feature = "derive", derive(ApfsData), apfs(bitflags_u32))]
    pub struct ReapListFLagsRaw: u32 {
        /// (`NRL_INDEX_INVALID`)
        const Invalid = 0xffffffff;

        const _ = !0;
    }
}

/// Reap list block (`nx_reap_list_phys_t`).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ReapListBlockRaw {
    /// Common block header (`nrl_o`)
    pub object: ObjectHeaderRaw,
    /// (`nrl_next`)
    pub next: ObjectIdentifierRaw,
    /// (`nrl_flags`)
    pub flags: ReapListFLagsRaw,
    /// (`nrl_max`)
    pub max: u32,
    /// (`nrl_count`)
    pub count: u32,
    /// (`nrl_first`)
    pub first: u32,
    /// (`nrl_last`)
    pub last: u32,
    /// (`nrl_free`)
    pub free: u32,
    /// (`nrl_entries`)
    #[cfg_attr(feature = "derive", apfs(trailing_data))]
    pub entries: [ReapListEntryRaw; 0],
}

impl DynamicSized for ReapListBlockRaw {
    type RangeBounds = Range<usize>;

    fn trailing_data_bounds(&self) -> Self::RangeBounds {
        let size = self.count as usize * core::mem::size_of::<ReapListEntryRaw>();

        0..size
    }
}

/// Phases used by the reaper when deleting from object maps.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u32)]
pub enum ObjectMapReapPhase {
    /// Reaper is deleting entries from the object mapping tree (`OMAP_REAP_PHASE_MAP_TREE`).
    MapTree = 1,

    /// Reaper is deleting entries from the snapshot tree (`OMAP_REAP_PHASE_SNAPSHOT_TREE`).
    SnapshotTree = 2,
}

/// State used to track reaping an object map (`omap_reap_state_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ObjectMapReapStateRaw {
    /// Phase the reaper is in (`omr_phase`).
    ///
    /// Value is [ObjectMapReapPhase].
    pub phase: u32,

    /// The key of the most recently freed entry in the object map (`omr_ok`).
    ///
    /// Facilitates resuming when interrupted.
    pub last_freed_key: ObjectMapKeyRaw,
}

/// State used when reaping deleted snapshots (`omap_cleanup_state_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ObjectMapCleanupStateRaw {
    /// Flag indicating whether the structure has valid data in it (`omc_cleaning`).
    ///
    /// 0 means the struct is empty. Otherwise it has data.
    pub cleaning: u32,

    /// Flags for the snapshot being deleted (`omc_omsflags`).
    ///
    /// Value is a [ObjectMapSnapshotFlagsRaw] and should match the flags stored in the
    /// [ObjectMapSnapshotRaw] instance.
    pub snapshot_flags: u32,

    /// Transaction ID of the snapshot before the snapshots being deleted (`omc_sxidprev`).
    pub previous_snapshot_xid: TransactionIdentifierRaw,

    /// Transaction ID of the first snapshot being deleted (`omc_sxidstart`).
    pub first_snapshot_xid: TransactionIdentifierRaw,

    /// Transaction ID of the last snapshot being deleted (`omc_sxidend`).
    pub last_snapshot_xid: TransactionIdentifierRaw,

    /// Transaction ID of the snapshot after the snapshots being deleted (`omc_sxidnext`).
    pub next_snapshot_xid: TransactionIdentifierRaw,

    /// The key of the next object mapping to consider for deletion (`omc_curkey`).
    pub current_key: ObjectMapKeyRaw,
}

/// Volume reaper states.
#[repr(u8)]
pub enum VolumeReaperState {
    /// (`APFS_REAP_PHASE_START`)
    Start = 0,
    /// (`APFS_REAP_PHASE_SNAPSHOTS`)
    Snapshots = 1,
    /// (`APFS_REAP_PHASE_ACTIVE_FS`)
    ActiveFilesystem = 2,
    /// (`APFS_REAP_PHASE_DESTROY_OMAP`)
    DestroyObjectMap = 3,
    /// (`APFS_REAP_PHASE_DONE`)
    Done = 4,
}

/// Volume reap state tracking (`apfs_reap_state_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C, packed)]
pub struct VolumeReapStateRaw {
    /// (`last_pbn`)
    pub last_pbn: u64,
    /// (`cur_snap_xid`)
    pub current_snapshot_xid: TransactionIdentifierRaw,
    /// (`phase`)
    ///
    /// Value is a [VolumeReaperState].
    pub phase: u32,
}
