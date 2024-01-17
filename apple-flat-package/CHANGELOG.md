# apple-flat package Crate Changelog

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

## 0.18.0

Released on 2024-01-17.

## 0.17.0

* scroll 0.11 -> 0.12.

Released on 2023-11-17.

## 0.16.0

Released on 2023-11-15.

* Types implementing `Serialize` and `Deserialize` all now derive `Eq` and
  `PartialEq`.
* The `PackageInfo` struct changed its storage of the `scripts` field
  so it can now properly decode `<scripts>` in XML files. (#9)
* `PkgReader::resolve_component()` is now public.
* The documentation for `PkgReader` has been clarified. (#14)

## 0.15.0

Released on 2023-11-09.

## 0.14.1

Released on 2023-11-09.

## 0.14.0

Released on 2023-11-06.

* Minimum supported Rust version is now 1.70.

## 0.13.0

Released on 2022-12-21.

* Cargo.toml now defines patch version for all dependencies.

## 0.12.0

Released on 2022-12-18.

## 0.11.0

Released on 2022-10-02.
