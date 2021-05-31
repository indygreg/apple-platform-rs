// Copyright 2022 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Interact with Apple BOM files.
//!
//! Apple Bill of Materials (BOM) files are a file format / data structure
//! for indexing file content with additional metadata. They are commonly
//! found in flat packages (e.g. `.pkg` files).
//!
//! This crate provides an interface for reading and writing Apple BOM
//! files.
//!
//! The gateway to reading support is [ParsedBom], which provides a read-only
//! interface to a BOM data structure.
//!
//! Writing support is still a work in progress.

pub mod builder;
pub mod error;
pub use error::Error;
pub mod format;
pub use format::ParsedBom;
pub mod path;

pub use path::{BomPath, BomPathType};
