# apple-sdk Crate Changelog

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

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
