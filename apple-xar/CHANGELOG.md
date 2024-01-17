# apple-xar Crate Changelog

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

## 0.18.0

Released on 2024-01-17.

* scroll 0.11 -> 0.12.

## 0.17.0

Released on 2023-11-17.

## 0.16.0

Released on 2023-11-15.

* Added the `signing` feature which controls whether Cryptographic
  Message Syntax based signing support is available. The feature -
  enabled by default - can be disabled to disable the `bcder`,
  `cryptographic-message-syntax`, `rand`, `reqwest`, and `signature`
  crates to significantly slim down the dependency tree. (#15)

## 0.15.0

Released on 2023-11-09.

* cryptographic-message-syntax 0.25 -> 0.26.
* x509-certificate 0.22 -> 0.23.

## 0.14.0

Released on 2023-11-06.

* Minimum supported Rust version is now 1.70.
* cryptographic-message-syntax 0.20 -> 0.25.
* signature 1.6 -> 2.0.
* x509-certificate 0.17 -> 0.22.

## 0.13.0

Released on 2022-12-21.

* Cargo.toml now defines patch version for all dependencies.

## 0.12.0

Released on 2022-12-18.

* `FileChecksum` now deserializes UPPERCASE string variants without
  error. (#51)

## 0.11.0

Released on 2022-10-02.
