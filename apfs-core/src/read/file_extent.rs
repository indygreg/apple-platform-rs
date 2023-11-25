// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! File extent reading.

use crate::block::{BlockRangeReader, BlockReader};
use apfs_types::data_stream::{FileExtentRecordKeyParsed, FileExtentRecordValueParsed};
use log::trace;
use std::io::Read;

struct ExtentRecordReader<'a, R: BlockReader> {
    reader: BlockRangeReader<'a, R>,
    len_bytes: u64,
    read_bytes: u64,
}

impl<'a, R: BlockReader> Read for ExtentRecordReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len_bytes - self.read_bytes;

        let dest = if buf.len() as u64 > remaining {
            &mut buf[0..remaining as usize]
        } else {
            buf
        };

        let count = self.reader.read(dest)?;

        trace!(
            "ExtentRecordReader read({}) @ {} -> {}",
            dest.len(),
            self.read_bytes,
            count
        );
        self.read_bytes += count as u64;

        Ok(count)
    }
}

struct ExtentHole {
    len_bytes: u64,
    read_bytes: u64,
}

impl Read for ExtentHole {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len_bytes - self.read_bytes;

        let dest = if buf.len() as u64 > remaining {
            &mut buf[0..remaining as usize]
        } else {
            buf
        };

        for x in dest.iter_mut() {
            *x = 0;
        }

        self.read_bytes += dest.len() as u64;
        Ok(dest.len())
    }
}

enum RopeEntry<'a, R: BlockReader> {
    Record(ExtentRecordReader<'a, R>),
    Hole(ExtentHole),
}

impl<'a, R: BlockReader> Read for RopeEntry<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Record(r) => r.read(buf),
            Self::Hole(h) => h.read(buf),
        }
    }
}

impl<'a, R: BlockReader> RopeEntry<'a, R> {
    fn eof(&self) -> bool {
        match self {
            Self::Record(r) => r.read_bytes == r.len_bytes,
            Self::Hole(h) => h.read_bytes == h.len_bytes,
        }
    }
}

/// A read interface for file extents.
///
/// Given a series of file extent records forming a logical rope, this
/// instance exposes an interface for reading data from the underlying
/// file extents.
///
/// Use this struct to resolve file content.
pub struct FileExtentReader<'a, R: BlockReader> {
    rope: Vec<RopeEntry<'a, R>>,
    rope_offset: usize,
}

impl<'a, R: BlockReader> FileExtentReader<'a, R> {
    pub fn new<'r>(
        reader: &'a R,
        records: impl Iterator<
            Item = (
                &'r FileExtentRecordKeyParsed,
                &'r FileExtentRecordValueParsed,
            ),
        >,
    ) -> Self {
        let mut rope = vec![];
        let mut offset = 0;

        for (k, v) in records {
            // There's a gap between this extent and what came before. Insert a hole
            // representing 0 bytes.
            if k.logical_address() > offset {
                rope.push(RopeEntry::Hole(ExtentHole {
                    len_bytes: k.logical_address() - offset,
                    read_bytes: 0,
                }));
                offset = k.logical_address();
            }

            let start_block = v.physical_block_number();
            let len_and_flags = v.length_and_flags();
            let len_bytes = len_and_flags.length();
            let block_count = len_bytes / reader.block_size() as u64;

            rope.push(RopeEntry::Record(ExtentRecordReader {
                reader: BlockRangeReader::new(reader, start_block, block_count),
                len_bytes,
                read_bytes: 0,
            }));
            offset += len_bytes;
        }

        Self {
            rope,
            rope_offset: 0,
        }
    }
}

impl<'a, R: BlockReader> Read for FileExtentReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        trace!("reading up to {} bytes from file extent reader", buf.len());
        let mut buf_offset = 0;

        while buf_offset < buf.len() && self.rope_offset < self.rope.len() {
            let dest = &mut buf[buf_offset..];
            assert!(
                !dest.is_empty(),
                "non-empty buffer ensured by loop condition"
            );

            let entry = &mut self.rope[self.rope_offset];

            let written = entry.read(dest)?;
            trace!("read {} bytes from file extent", written);
            buf_offset += written;

            if entry.eof() {
                self.rope_offset += 1;
            }

            if written == 0 {
                break;
            }
        }

        Ok(buf_offset)
    }
}
