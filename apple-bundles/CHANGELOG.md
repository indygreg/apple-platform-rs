# apple-bundles Crate Changelog

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

* MSRV 1.81 -> 1.86.

## 0.21.0

Released on 2024-11-29.

## 0.20.0

Released on 2024-11-03.

* `DirectoryBundle::info_plist_path()` now returns the path the instance was
  constructed with instead of deriving it at call time. Previously, the
  derivation logic could disagree with the constructed value. (#157)
* `plist` 1.6.0 -> 1.7.0.
* `walkdir` 2.4 -> 2.5.

## 0.19.0

Released on 2024-01-17.

## 0.18.0

Released on 2023-11-06.

* Minimum supported Rust version is now 1.70.

## 0.17.0

Released on 2022-12-21.

* Cargo.toml now defines patch version for all dependencies.
* Minimum supported Rust version is now 1.65.

## 0.16.0

Released on 2022-12-18.

* Look for `Info.plist` in correct location in shallow framework bundles. This
  fixes an issue where shallow framework bundles weren't correctly identified
  as such. (#46)

## 0.15.0

Released on 2022-10-02.
