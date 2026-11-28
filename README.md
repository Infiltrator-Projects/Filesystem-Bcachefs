# Filesystem-Bcachefs

Native Common V2 recognition development for single-member Bcachefs. The implementation checks actual redundant superblock layout, UUIDs, checksums, bounded variable records and native member geometry. Only CORE PROBE is exposed. No B-tree, snapshot, journal replay, mount or mutation is claimed. Unknown checksum types, features requiring an unimplemented decoder and multi-member media are not a supported mount profile. Exact-source CI uses independent formatter images, fixtures and sanitizers. Published v0.0.1 remains documentation-only.

[Manual](docs/Bcachefs.pdf) · [Technical reference](docs/Bcachefs-TECHNICAL-REFERENCE.md) · [Migration status](MIGRATION_STATUS.md) · [Native design](native/filesystems/bcachefs/DESIGN.md) · [Common V2](https://github.com/Infiltrator-Projects/Libraries)
