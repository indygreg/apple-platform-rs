// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use apfs_types::common::{EphemeralObjectIdentifierRaw, VirtualObjectIdentifierRaw};
use apfs_types::ParseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApfsError {
    #[error("APFS parse error {0}")]
    ApfsParse(ParseError),
    #[error("no superblock found")]
    NoSuperblock,
    #[error("input data slice too small")]
    InputTooSmall,
    #[error("data structure isn't aligned")]
    NonAligned,
    #[error("malformed trailing bounds: {0}")]
    TrailingBoundsMalformed(&'static str),
    #[error("invalid fletcher64 checksum")]
    InvalidChecksum,
    #[error("invalid file system object type")]
    InvalidFileSystemObjectType,
    #[error("string data not NULL terminated")]
    StringNotNullTerminated,
    #[error("string data not valid UTF-8")]
    StringNotUtf8,
    #[error("B-tree node is not a root")]
    BTreeNodeNotRoot,
    #[error("unimplemented: {0}")]
    Unimplemented(&'static str),
    #[error("ephemeral object id {0} not found")]
    EphemeralObjectNotFound(EphemeralObjectIdentifierRaw),
    #[error("virtual object id {0} not found")]
    VirtualObjectNotFound(VirtualObjectIdentifierRaw),
    #[error("block read error: {0}")]
    BlockRead(#[from] crate::block::BlockReadError),
    #[error("reaper not found")]
    ReaperNotFound,
    #[error("space manager not found")]
    SpaceManagerNotFound,
    #[error("missing inode record on filesystem entry")]
    FileNoInode,
    #[error("inode missing name")]
    InodeNoName,
    #[error("inode parent not found")]
    InodeMissingParent,
    #[error("inode missing data stream attribute")]
    InodeNoDataStream,
    #[error("path is empty")]
    PathEmpty,
    #[error("path is not absolute")]
    PathNotAbsolute,
    #[error("invalid component in path")]
    PathInvalidComponent,
    #[error("path not found")]
    PathNotFound,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ParseError> for ApfsError {
    fn from(value: ParseError) -> Self {
        Self::ApfsParse(value)
    }
}

pub type Result<T, E = ApfsError> = std::result::Result<T, E>;
