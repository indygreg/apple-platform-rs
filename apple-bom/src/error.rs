// Copyright 2022 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("(de)serialization error: {0}")]
    Scroll(#[from] scroll::Error),

    #[error("unable to parse variable name as UTF-8")]
    BadVariableString,

    #[error("bad index into BOM data")]
    BadIndex,

    #[error("data type {0} not found")]
    NoVar(String),

    #[error("illegal BOM path \"{0}\": {1}")]
    BadPath(String, &'static str),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("bad arguments: {0}")]
    CliBadArgs(String),

    #[error("unknown block type")]
    UnknownBlockType,

    #[error("invalid time value")]
    BadTime,
}
