# app-store-connect Crate Changelog

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

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
