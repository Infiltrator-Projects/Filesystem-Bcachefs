# Filesystem-Bcachefs

Native Common V2 recognition development for single-member Bcachefs. The implementation checks actual redundant superblock layout, UUIDs, checksums, bounded variable records, native member geometry, both journal-bucket encodings and clean-section root record bounds. Only CORE PROBE is exposed. No B-tree, snapshot, journal replay, mount or mutation is claimed. Unknown checksum types, features requiring an unimplemented decoder and multi-member media are not a supported mount profile. Exact-source CI uses independent formatter images, fixtures and sanitizers. Published v0.0.1 remains documentation-only.

[Manual](docs/Bcachefs.pdf) · [Technical reference](docs/Bcachefs-TECHNICAL-REFERENCE.md) · [Migration status](MIGRATION_STATUS.md) · [Native design](native/filesystems/bcachefs/DESIGN.md) · [Common V2](https://github.com/Infiltrator-Projects/Libraries)

Clean-section root pointers now lead to the actual on-disk root nodes. The decoder checks native node identity, sequence, checksummed bset records, bounded packed key format, logical key ordering and journal-sequence bounds. This is structural root validation only; effective key-set merge, allocation generations, snapshot visibility and the mounted namespace remain unimplemented. The independent formatter test does not establish a populated clean B-tree.
