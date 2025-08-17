# app-store-connect Crate Changelog

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

* MSRV 1.81 -> 1.86.

## 0.7.0

Released on 2024-11-29.

* MSRV 1.78 -> 1.81.
* `clap` 4.4 -> 4.5.
* `jsonwebtoken` 9.2 -> 9.3.
* `thiserror` 1.0 -> 2.0.

## 0.6.0

Released on 2024-11-03.

* New APIs and CLI commands to: list capabilities with a bundle ID;
  list profiles associated with a bundle ID; get bundle ID associated with
  a profile; list certificates associated with a profile; enable capacity
  for a bundle ID. (#164)
* Added `IosDistribution` variant to `CertificateType` enum.
* Enabled `http2` feature of `reqwest` crate. This may provide better HTTP/2.0
  compatibility.
* MSRV 1.70 -> 1.78.
* `base64` 0.21 -> 0.22.
* `env_logger` 0.10 -> 0.11.
* `reqwest` 0.11 -> 0.12
* `x509-certificate` 0.23 -> 0.24.

## 0.5.0

Released on 2024-01-17.

## 0.4.0

Released on 2023-11-15.

## 0.3.0

Released on 2023-11-09.

* x509-certificate 0.22 -> 0.23.

## 0.2.0

Released on 2023-11-06.

* Minimum supported Rust version changed from 1.62 to 1.64.
* CLI code moved from `main.rs` to a `cli` module.
* HTTP requests now use the operating system's trusted X.509 certificates
  instead of a default set (based off Mozilla's maintained list). This should
  allow connections to HTTP proxies using custom/private certificate authorities
  to work, assuming certificates are installed on the local system. (#85)
* jsonwebtoken 8.3 -> 9.1.
* pem 1.1 -> 3.0.
* rsa 0.7 -> 0.8.
* x509-certificate 0.16 -> 0.22.
* dirs 4.0.0 -> 5.0.0.
* Minimum supported Rust version is now 1.70.

## 0.1.0

Released on 2022-12-21.

* Initial version of crate. Code borrowed and extended from apple-codesign crate.
