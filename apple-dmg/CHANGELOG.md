# apple-dmg Crate Changelog

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

* `DmgReader` gained some methods to read the raw XML plist data.
* Reading zero and ignore type chunks now emits the proper number of 0
  bytes. This fixes a bug where these chunks weren't sized properly,
  resulting in an incorrect extraction of partition data.

## 0.5.0

Released on 2024-11-03.

* gpt 3.1 -> 4.0.

## 0.4.0

Released on 2023-11-15.

## 0.3.1

Released on 2023-11-09.

## 0.3.0

Released on 2023-11-06.

* Minimum supported Rust version is now 1.70.

## 0.2.0

Released on 2022-12-21.
