// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Debug;
use std::io::{Read, Seek};

pub mod container;
pub mod file_extent;
pub mod filesystem;
pub mod volume;

/// Describes a reader that can read from a std::io::Read interface.
pub trait FilesystemReader: Debug + Read + Seek + Send {}

impl FilesystemReader for std::fs::File {}

impl FilesystemReader for std::io::Cursor<Vec<u8>> {}
