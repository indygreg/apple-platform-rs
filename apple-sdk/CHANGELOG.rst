=========================
apple-sdk Crate Changelog
=========================

0.2.0
=====

Released on 2022-07-31.

* Document that ``SdkSearchLocation::SdkRootEnv`` bypasses SDK filtering.
* Add ``Platform::from_target_triple()``. (#1)
* ``AppleSdk::as_sdk_path()`` has been renamed to ``AppleSdk::sdk_path()``. The
  old name proxies to the new function, is marked as deprecated, and will be
  removed in a future minor version release. (#2)

0.1.0
=====

Released on 2022-05-26.

Initial version of crate.
