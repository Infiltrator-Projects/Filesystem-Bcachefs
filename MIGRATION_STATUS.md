# Bcachefs Common V2 migration

Independent recognition implements native superblock layout, single-device membership, CRC32C/CRC64 (with native seed variants), copy identity and sequence selection, and length-bounded typed fields. Reference: [pinned original format and checksum code](https://github.com/Infiltrator-Projects/Filesystems/tree/101026021d9088d80b7f0f472d9061f0e2c688a3/native/filesystems/bcachefs). Original source attribution remains intact; new code is GPL-3.0-or-later.

CORE PROBE only. B-tree packed keys and root state, journal and snapshot visibility, allocation, namespace, checksummed payloads, mutation, defragmentation, recovery and physical BOOT/kernel qualification remain outstanding. Runtime publication is not attempted at this stage. Independent media and sanitizer results must be verified at the exact revision.

## Native journal bootstrap

Recognition now validates declared journal buckets and non-overlapping journal ranges against the member geometry, matches redundant member identities, and decodes clean-section journal record lengths, native root key shape and single-member pointer bounds. These are bounded bootstrap checks; root-node reading, node-local key decoding, journal reconciliation, allocation generations and namespace traversal remain outstanding. Checksummed malformed journal and root fixtures are mandatory in CI.
