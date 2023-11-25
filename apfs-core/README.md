# apfs-core

`apfs-core` implements business logic for the Apple File System (APFS).

Whereas the `apfs-types` crate defines the primitive data structures in
APFS, `apfs-core` contains the code for doing things with them, such as
reading filesystem content.

Known limitations:

* Only reading is implemented. Writing support is tentatively planned.
* Crate relies on std and alloc features and cannot be used to implement a
  kernel mode APFS driver. Patches to remove these dependencies will be
  welcomed.
* Error handling is not robust. There need to be more granular error types
  instead of monolithic error types.
* Very little performance optimization. e.g. B-tree lookups aren't optimized.
  Performance is likely poor, especially on larger filesystems. There are no
  caches, so blocks will be frequently read from underlying I/O.
* Limited testing and security hardening.

That bullet list effectively says that this crate provides an alpha level
implementation of APFS. Use at your own risk.

Furthermore, the original author of this crate has no intention to evolve this
crate into a production level implementation of APFS. If you would like to
maintain this APFS implementation, please get in touch with Gregory Szorc.
