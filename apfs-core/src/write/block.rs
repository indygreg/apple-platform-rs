// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Block writing / mutation.

use crate::block::{fletcher64, Block};
use apfs_types::common::PhysicalObjectIdentifierRaw;
use bytes::BytesMut;
use std::ops::{Deref, DerefMut};

#[derive(Clone)]
pub struct MutBlock {
    number: PhysicalObjectIdentifierRaw,
    buf: BytesMut,
}

impl Deref for MutBlock {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl DerefMut for MutBlock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl MutBlock {
    /// Construct a new block consisting of all 0s.
    pub fn new_zeroed(number: impl Into<PhysicalObjectIdentifierRaw>, size_bytes: usize) -> Self {
        Self {
            number: number.into(),
            buf: BytesMut::zeroed(size_bytes),
        }
    }

    /// Freeze state and convert into a read-only [Block], consuming self.
    ///
    /// This is a very efficient operation.
    ///
    /// Note: does not compute the block checksum.
    pub fn freeze(self) -> Block {
        Block::new(self.number, self.buf.freeze())
    }

    /// Obtain a [Block] from self without consuming self.
    ///
    /// This clones the inner buffer without any modifications.
    pub fn to_block(&self) -> Block {
        self.clone().freeze()
    }

    /// Write out the checksum from current block contents.
    ///
    /// Consumes self as a hint to caller that further modifications will invalidate checksum.
    pub fn derive_checksum(mut self) -> Self {
        let checksum = fletcher64(&self.buf.as_ref()[8..]);
        let dest = &mut self.buf.as_mut()[0..8];
        dest.copy_from_slice(&checksum.to_le_bytes());

        self
    }

    /// Compute and set the checksum and freeze the block.
    pub fn checksum_and_freeze(mut self) -> Block {
        self.derive_checksum().freeze()
    }
}
