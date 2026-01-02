# apple-sdk Crate Changelog

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

* Ignore SDK-like directories having the name `AssetRuntime.*`, which we
  believe to be invalid.
* MSRV 1.81 -> 1.88.

## 0.6.0

Released on 2024-11-03.

* XROS support. `Platform` enumeration added `XrOs` and `XrOsSimulator`
  variants. The `aarch64-apple-xros-sim` and `*-apple-xros` triples are
  now recognized as XROS.
* The developer directory configured with `xcode-select --switch PATH` can now
  be retrieved by using `DeveloperDirectory::from_xcode_select_paths`, and
  this is done by default when searching for SDKs. (#154)
* `plist` 1.6 -> 1.7.

## 0.5.2

Released on 2023-12-22.

* Fixed repository URL in README.md.

## 0.5.1

Released on 2023-11-09.

## 0.5.0

Released on 2023-11-06.

* Change `PlatformDirectory` and `SdkVersion` `partial_cmp()` to be
  implemented in terms of `cmp()`. Should have no visible effects.

## 0.4.0

Released on 2022-12-21.

* Cargo.toml now defines patch version for all dependencies.

## 0.3.0

Released on 2022-12-18.

* Project moved from https://github.com/indygreg/toolchain-tools to
  https://github.com/indygreg/apple-platform-rs.

## 0.2.0

Released on 2022-07-31.

* Document that `SdkSearchLocation::SdkRootEnv` bypasses SDK filtering.
* Add `Platform::from_target_triple()`. (#1)
* `AppleSdk::as_sdk_path()` has been renamed to `AppleSdk::sdk_path()`. The
  old name proxies to the new function, is marked as deprecated, and will be
  removed in a future minor version release. (#2)

## 0.1.0

Released on 2022-05-26.

Initial version of crate.
