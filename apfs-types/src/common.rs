// Copyright 2023 Gregory Szorc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Common types and functionality.

use core::fmt::{Debug, Display, Formatter};
use core::ops::{Add, Deref, Mul, Sub};

#[cfg(feature = "derive")]
use apfs_derive::ApfsData;

/// A universal unique identifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct UuidRaw(pub [u8; 16]);

impl Deref for UuidRaw {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An object identifier that is guaranteed to be a physical object.
///
/// A more strongly typed version of [ObjectIdentifierRaw].
///
/// Physical object identifiers denote block numbers where an entity resides.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct PhysicalObjectIdentifierRaw(pub u64);

impl Deref for PhysicalObjectIdentifierRaw {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for PhysicalObjectIdentifierRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl From<PhysicalObjectIdentifierRaw> for u64 {
    fn from(value: PhysicalObjectIdentifierRaw) -> Self {
        value.0
    }
}

impl From<u64> for PhysicalObjectIdentifierRaw {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<PhysicalAddressRaw> for PhysicalObjectIdentifierRaw {
    fn from(value: PhysicalAddressRaw) -> Self {
        Self(value.0 as u64)
    }
}

impl Mul<Self> for PhysicalObjectIdentifierRaw {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Add<Self> for PhysicalObjectIdentifierRaw {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<u64> for PhysicalObjectIdentifierRaw {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

/// An object identifier that is guaranteed to be an ephemeral object.
///
/// A more strongly typed version of [ObjectIdentifierRaw].
///
/// Ephemeral objects are loaded into memory from checkpoint data when
/// loading a container.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct EphemeralObjectIdentifierRaw(pub u64);

impl Deref for EphemeralObjectIdentifierRaw {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for EphemeralObjectIdentifierRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl From<EphemeralObjectIdentifierRaw> for u64 {
    fn from(value: EphemeralObjectIdentifierRaw) -> Self {
        value.0
    }
}

impl From<u64> for EphemeralObjectIdentifierRaw {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// An object identifier that is guaranteed to be a virtual object.
///
/// A more strongly typed version of [ObjectIdentifierRaw].
///
/// Virtual objects are resolved through object maps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct VirtualObjectIdentifierRaw(pub u64);

impl Deref for VirtualObjectIdentifierRaw {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for VirtualObjectIdentifierRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl From<VirtualObjectIdentifierRaw> for u64 {
    fn from(value: VirtualObjectIdentifierRaw) -> Self {
        value.0
    }
}

impl From<u64> for VirtualObjectIdentifierRaw {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// A generic object identifier (`oid_t`).
///
/// Object identifiers have different meanings depending on their
/// context. A specific identifier may refer to:
///
/// * A block number for *physical* objects.
/// * A tracking number for an *ephemeral* object (location resolves to
///   in-memory data structures loaded from checkpoint area).
/// * A tracking number for a *virtual* object (location resolved through
///   an object map).
///
/// Use of a more strongly typed wrapper identifier ([PhysicalObjectIdentifierRaw],
/// [EphemeralObjectIdentifierRaw], or [VirtualObjectIdentifierRaw]) is strongly
/// preferred since it yields stronger type safety.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct ObjectIdentifierRaw(pub u64);

impl Deref for ObjectIdentifierRaw {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u64> for ObjectIdentifierRaw {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<ObjectIdentifierRaw> for u64 {
    fn from(value: ObjectIdentifierRaw) -> Self {
        value.0
    }
}

impl From<PhysicalObjectIdentifierRaw> for ObjectIdentifierRaw {
    fn from(value: PhysicalObjectIdentifierRaw) -> Self {
        Self(value.0)
    }
}

impl From<ObjectIdentifierRaw> for PhysicalObjectIdentifierRaw {
    fn from(value: ObjectIdentifierRaw) -> Self {
        Self(value.0)
    }
}

impl From<EphemeralObjectIdentifierRaw> for ObjectIdentifierRaw {
    fn from(value: EphemeralObjectIdentifierRaw) -> Self {
        Self(value.0)
    }
}

impl From<ObjectIdentifierRaw> for EphemeralObjectIdentifierRaw {
    fn from(value: ObjectIdentifierRaw) -> Self {
        Self(value.0)
    }
}

impl From<VirtualObjectIdentifierRaw> for ObjectIdentifierRaw {
    fn from(value: VirtualObjectIdentifierRaw) -> Self {
        Self(value.0)
    }
}

impl From<ObjectIdentifierRaw> for VirtualObjectIdentifierRaw {
    fn from(value: ObjectIdentifierRaw) -> Self {
        Self(value.0)
    }
}

/// Transaction identifier (`xid_t`).
///
/// Often abbreviated to `xid` in field names.
///
/// Transaction identifiers are monotonically increasing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct TransactionIdentifierRaw(pub u64);

impl Deref for TransactionIdentifierRaw {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for TransactionIdentifierRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl From<u64> for TransactionIdentifierRaw {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<TransactionIdentifierRaw> for u64 {
    fn from(value: TransactionIdentifierRaw) -> Self {
        value.0
    }
}

/// A physical address / block number (`paddr_t`).
///
/// Negative values aren't valid. The use of i64 is to preserve compatibility
/// with Apple's API.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct PhysicalAddressRaw(pub i64);

impl Deref for PhysicalAddressRaw {
    type Target = i64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for PhysicalAddressRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Add<Self> for PhysicalAddressRaw {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<i32> for PhysicalAddressRaw {
    type Output = Self;

    fn add(self, rhs: i32) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}

impl Add<u32> for PhysicalAddressRaw {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}

impl Add<i64> for PhysicalAddressRaw {
    type Output = Self;

    fn add(self, rhs: i64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl Add<u64> for PhysicalAddressRaw {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}

impl Sub<Self> for PhysicalAddressRaw {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Sub<i64> for PhysicalAddressRaw {
    type Output = Self;

    fn sub(self, rhs: i64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl From<i64> for PhysicalAddressRaw {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<PhysicalAddressRaw> for i64 {
    fn from(value: PhysicalAddressRaw) -> Self {
        value.0
    }
}

impl From<PhysicalAddressRaw> for u64 {
    fn from(value: PhysicalAddressRaw) -> Self {
        value.0 as _
    }
}

impl From<PhysicalAddressRaw> for usize {
    fn from(value: PhysicalAddressRaw) -> Self {
        value.0 as _
    }
}

/// Represents a span of physical blocks (`prange_t`).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct PhysicalAddressRangeRaw {
    /// The starting block address (`pr_start_paddr`).
    pub start_address: PhysicalAddressRaw,
    /// The number of blocks in the span (`pr_block_count`).
    pub block_count: u64,
}

/// An APFS filesystem time.
///
/// Nanoseconds since UNIX epoch without leap seconds.
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "derive", derive(ApfsData))]
#[repr(C)]
pub struct TimeRaw(pub u64);

impl Deref for TimeRaw {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for TimeRaw {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let dt = self.as_utc_datetime().unwrap_or_default();

        f.debug_tuple("Time").field(&dt).finish()
    }
}

impl From<u64> for TimeRaw {
    fn from(time: u64) -> Self {
        Self(time)
    }
}

impl From<TimeRaw> for u64 {
    fn from(value: TimeRaw) -> Self {
        value.0
    }
}

impl TimeRaw {
    /// Convert the value to a UTC date-time.
    pub fn as_utc_datetime(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        let seconds = self.0 / 1_000_000_000;
        let nanos = self.0 % 1_000_000_000;

        chrono::DateTime::from_timestamp(seconds as _, nanos as _)
    }
}
