// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Plain-old-data data manipulation routines.
//!
//! This module defines some primitives to facilitate munging APFS data
//! structure to/from their on-disk form.

use crate::{DiskStruct, DynamicSized, ParseError, ParsedDiskStruct, StaticSized};
use bytes::Bytes;
use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;
use core::ops::{Bound, Deref, RangeBounds};

/// A `std::borrow::Cow` like primitive.
///
/// We have to reinvent the wheel since we're a no-std crate.
pub enum OwnedOrBorrowed<'a, T> {
    Owned(T),
    Borrowed(&'a T),
}

impl<'a, T> Deref for OwnedOrBorrowed<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(v) => v,
            Self::Borrowed(v) => v,
        }
    }
}

impl<'a, T> AsRef<T> for OwnedOrBorrowed<'a, T> {
    fn as_ref(&self) -> &T {
        match self {
            Self::Owned(x) => x,
            Self::Borrowed(x) => x,
        }
    }
}

impl<T: Clone> Clone for OwnedOrBorrowed<'_, T> {
    fn clone(&self) -> Self {
        match self {
            Self::Owned(x) => Self::Owned(x.clone()),
            Self::Borrowed(x) => Self::Borrowed(x),
        }
    }
}

impl<T: Debug> Debug for OwnedOrBorrowed<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple(if self.is_owned() { "Owned" } else { "Borrowed" })
            .field(self.as_ref())
            .finish()
    }
}

impl<T> OwnedOrBorrowed<'_, T> {
    pub fn is_owned(&self) -> bool {
        matches!(self, Self::Owned(_))
    }

    pub fn is_borrowed(&self) -> bool {
        matches!(self, Self::Borrowed(_))
    }
}

/// Represents a loaded APFS data structure.
#[derive(Clone)]
pub struct ApfsDataStructure<'a, T: DiskStruct> {
    buf: Option<Bytes>,
    inner: OwnedOrBorrowed<'a, T>,
}

impl<'a, T: DiskStruct> AsRef<T> for ApfsDataStructure<'a, T> {
    fn as_ref(&self) -> &T {
        self.inner.as_ref()
    }
}

impl<'a, T: DiskStruct> Deref for ApfsDataStructure<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: DiskStruct + Debug> Debug for ApfsDataStructure<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.inner.fmt(f)
    }
}

impl<'a, T: DiskStruct> ApfsDataStructure<'a, T> {
    /// Cast some raw bytes into a reference to the generic type.
    ///
    /// If called on a big-endian machine, integer fields will likely be
    /// incorrect.
    fn cast_bytes(data: &[u8]) -> Result<&'a T, ParseError> {
        let size = core::mem::size_of::<T>();

        if data.len() < size {
            return Err(ParseError::InputTooSmall);
        }

        let ptr = data.as_ptr();

        // Can only cast if memory is properly aligned.
        if (ptr as usize) % core::mem::align_of::<T>() == 0 {
            Ok(unsafe { &*ptr.cast() })
        } else {
            Err(ParseError::NonAligned)
        }
    }
}

impl<'a, T: DiskStruct + StaticSized> ApfsDataStructure<'a, T> {
    /// Construct a new instance of a static sized struct.
    ///
    /// A static sized struct is one without any trailing data.
    ///
    /// If `retain_input` is false, the input buffer may or may not be retained
    /// in the returned struct: it depends on the endianness of the current machine
    /// and whether the underlying data buffer is properly aligned.
    ///
    /// If `retain_input` is true, we always retain the source bytes.
    pub fn new_static_sized(buf: Bytes, retain_input: bool) -> Result<Self, ParseError> {
        if cfg!(target_endian = "little")
            && ((buf.as_ptr() as usize) % core::mem::align_of::<T>() == 0)
        {
            let inner = OwnedOrBorrowed::Borrowed(Self::cast_bytes(buf.as_ref())?);

            Ok(Self {
                buf: Some(buf),
                inner,
            })
        } else {
            let inner = OwnedOrBorrowed::Owned(T::parse_bytes(buf.as_ref())?);
            let buf = if retain_input { Some(buf) } else { None };

            Ok(Self { buf, inner })
        }
    }
}

impl<'a, T: DiskStruct + DynamicSized> ApfsDataStructure<'a, T> {
    /// Construct a new instance of a dynamically sized type.
    ///
    /// The input buffer is always fully captured. This allows trailing
    /// data to be retrieved and decoded later.
    pub fn new_dynamic_sized(buf: Bytes) -> Result<Self, ParseError> {
        let inner = if cfg!(target_endian = "little")
            && ((buf.as_ptr() as usize) % core::mem::align_of::<T>() == 0)
        {
            OwnedOrBorrowed::Borrowed(Self::cast_bytes(buf.as_ref())?)
        } else {
            OwnedOrBorrowed::Owned(T::parse_bytes(buf.as_ref())?)
        };

        Ok(Self {
            buf: Some(buf),
            inner,
        })
    }

    /// Obtain the raw backing data for this data structure.
    ///
    /// This is effectively a reference to the bytes used to construct the instance.
    /// The bytes may be in a different endian from the constructed instance.
    /// Changes to the bytes (if unsafe is abused) may or may not be reflected
    /// in the data structure attached to this instance.
    pub fn bytes(&self) -> Bytes {
        self.buf
            .clone()
            .expect("should always retain backing data for dynamically sized types")
    }

    /// Obtain the trailing data after the fixed size data structure header.
    ///
    /// The first byte in the slice is the first byte after the fixed size header.
    pub fn trailing_data(&self) -> Result<Bytes, ParseError> {
        // Get the trailing slice.
        let remaining = self.bytes().slice(T::trailing_data_offset()..);

        // Then truncate it as appropriate for the current data structure.
        let bounds = self.inner.trailing_data_bounds();

        // This is arbitrary to simplify logic. But it should always be true.
        if !matches!(bounds.start_bound(), Bound::Included(0)) {
            panic!("trailing bounds malformed; expected start index of 0; you found a bug in the apfs-types crate");
        }

        let length = match bounds.end_bound() {
            Bound::Included(offset) => *offset + 1,
            Bound::Excluded(offset) => *offset,
            Bound::Unbounded => remaining.len(),
        };

        if remaining.len() < length {
            return Err(ParseError::InputTooSmall);
        }

        let trailing = remaining.slice(0..length);

        Ok(trailing)
    }
}

/// A generic interface to an in-memory array of C-compatible structs.
///
/// Generic type parameters define the raw and parsed variant.
///
/// Instances effectively hold a buffer pointing to the start of the array.
/// Instances can iterate over elements in the array. Iteration triggers
/// lazy parsing of elements into the parsed variants.
#[derive(Clone)]
pub struct MemoryBackedArray<I: DiskStruct, O: ParsedDiskStruct> {
    input: PhantomData<I>,
    output: PhantomData<O>,
    buf: Bytes,
    count: usize,
}

impl<I: DiskStruct, O: ParsedDiskStruct + Debug> Debug for MemoryBackedArray<I, O> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<I: DiskStruct, O: ParsedDiskStruct> MemoryBackedArray<I, O> {
    /// Construct an instance from a memory span having `count` elements.
    pub fn new(buf: Bytes, count: usize) -> Result<Self, ParseError> {
        let needed = count * core::mem::size_of::<I>();

        if buf.len() < needed {
            return Err(ParseError::InputTooSmall);
        }

        Ok(Self {
            input: PhantomData,
            output: PhantomData,
            buf,
            count,
        })
    }

    /// Obtain the number of elements in this array.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether this array is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the element at the specified index.
    pub fn get(&self, index: usize) -> Option<Result<O, ParseError>> {
        if index >= self.count {
            None
        } else {
            let start = index * core::mem::size_of::<I>();

            let buf = self.buf.slice(start..);

            Some(O::from_bytes(buf))
        }
    }

    /// Iterate over all items in this array.
    ///
    /// Items are parsed for every call. So callers should cache resolved values
    /// in performance sensitive contexts.
    pub fn iter(&self) -> impl Iterator<Item = Result<O, ParseError>> + '_ {
        (0..self.count).map(|i| self.get(i).expect("index should be valid"))
    }
}

/// A NULL-terminated UTF-8 string.
///
/// APFS strings are stored as NULL-terminated UTF-8 strings. This type
/// models those values.
///
/// Instances only store a [Bytes]. At construction time, the memory
/// data is validated. This enables lightweight conversion to `&str`.
#[derive(Clone)]
pub struct ApfsString {
    buf: Bytes,
}

impl ApfsString {
    pub fn from_bytes(buf: Bytes) -> Result<Self, ParseError> {
        if let Some(last) = buf.last() {
            if !*last == 0 {
                return Err(ParseError::StringNotNullTerminated);
            }
        } else {
            return Err(ParseError::InputTooSmall);
        }

        if core::str::from_utf8(buf.as_ref()).is_ok() {
            Ok(Self { buf })
        } else {
            Err(ParseError::StringNotUtf8)
        }
    }

    /// Coerce self to a &str.
    ///
    /// This is a lightweight conversion.
    pub fn as_str(&self) -> &str {
        // Constructor validated the data is NULL terminated UTF-8. So should be safe.
        unsafe { core::str::from_utf8_unchecked(&self.buf.as_ref()[0..self.buf.len() - 1]) }
    }
}

impl Debug for ApfsString {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("ApfsString").field(&self.as_str()).finish()
    }
}

impl TryFrom<Bytes> for ApfsString {
    type Error = ParseError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}
