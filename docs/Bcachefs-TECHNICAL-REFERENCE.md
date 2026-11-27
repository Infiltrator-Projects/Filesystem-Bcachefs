# Bcachefs: technical reference

## Scope and design

Bcachefs, developed by Kent Overstreet, evolved from bcache's storage-management techniques into a copy-on-write filesystem. It entered the Linux kernel in version 6.7. This reference is pinned to Linux v6.12, rather than treating later metadata revisions as interchangeable. Its three principal persistent structures are the superblock, journal and B-trees. Extents, inode records, directory entries, allocation state and snapshot relationships are represented by typed keys in different trees. Large nodes contain appendable sorted key sets; new node allocations and journal replay preserve consistent metadata ordering. This is not an ext4-style block-group filesystem. The source version defines the scope, and later format versions require independent study.

## Superblock discovery and layout

Addresses use 512-byte sectors unless a field explicitly specifies another unit. The default superblock begins at sector 8 (byte 4096). A layout record begins at sector 7 (byte 3584), and is also embedded in each superblock. Its offsets are: magic UUID at byte 0, layout type at 16, maximum size exponent at 17, copy count at 18, five padding bytes at 19, and 61 little-endian 64-bit sector locations at 24. Its total size is 512 bytes. A maximum size exponent of 16 corresponds to 32 MiB; validate the bound, count and all copy ranges before reading. Backup copies need not be at fixed offsets. Never assume all devices have identical journal locations.

## Superblock prefix and extension fields

The superblock begins with a 16-byte checksum, two 16-bit format versions at offsets 16 and 18, four reserved bytes at 20, magic UUID at 24, internal UUID at 40 and user UUID at 56. The label follows. Subsequent fields record the physical superblock sector, sequence number, filesystem block size, member index and count, extension size, time base and precision, flags, write time, incompatible features, compatibility features and embedded layout. Version_min describes the oldest metadata encoding still present, not merely the desired version. After the fixed header, variable records start with a little-endian 32-bit total length in 64-bit words and a 32-bit type. A zero length, out-of-range record or unknown required feature must prevent unsafe interpretation.

## Typed superblock sections and membership

In v6.12 the field type IDs include journal 0, members_v1 1, crypt 2, replicas_v0 3, quota 4, disk groups 5, clean 6, replicas 7, journal blacklist 8, journal_v2 9, counters 10, members_v2 11, errors 12, extension 13 and downgrade 14. Member records start with a UUID at 0, bucket count at 16, first bucket at 24 and bucket size in sectors at 26. Validate record size according to the relevant members section version. Combine sector, bucket and device identity before any media access. Select consistent checksum-valid superblocks, taking sequence and membership into account; a high sequence number on a mismatched device is not evidence of a newer coherent filesystem.

## Common key encoding

A key/value record begins with an 8-bit total size in 64-bit words, a format/whiteout byte, and a value-type byte. For little-endian encoding, the low seven bits of the second byte specify format and the highest bit is needs-whiteout. Format 0 denotes node-local packing; 1 denotes the current unpacked representation. The logical position contains a 64-bit inode, 64-bit offset and 32-bit snapshot ID. Additional fields describe extent length and 96-bit version. The unpacked little-endian position orders snapshot, offset and inode in memory, whereas big-endian layouts differ. Key order must follow logical comparison rules, not an arbitrary bytewise comparison. Bound each record by both key-header size and containing set length.

The retained format header defines packed key widths and inode/offset/snapshot positions. Validate key and value lengths before decoding; nonmonotone keys and unverified device membership invalidate traversal. Kent Overstreet's 2018 public on-disk data structures patch is an early design reference, not a substitute for revision-specific feature negotiation.

## Node-local packed keys

Each B-tree node contains a 56-byte packing description: key length in 64-bit words at 0, field count at 1, six field widths at 2, and six little-endian 64-bit base offsets at 8. The field order is inode, offset, snapshot, size, version high and version low. Packed data begins after the 24-bit common prefix; it represents field values relative to the format's bases. Decode using the specified bit ordering and node byte-order state, validate widths and check addition overflow. Do not mistake the in-memory padding of a packed-key C structure for persistent record length. A zero-width field is a constant represented by its base. The upstream bkey packing routines are necessary references for exact bit extraction, byte-swapping and comparison.

## Node and key-set organisation

A B-tree node header has a 16-byte checksum, 64-bit magic at 16, 64-bit flags at 24, closed minimum and maximum key positions at 32 and 52, an obsolete eight-byte pointer at 72, and the packing description at 80. In the v6.12 layout the first key-set header follows at 136. The node flags encode tree ID in bits 0..3 and 9..24, tree level in 4..7 and node sequence in 32..63. Key-set headers hold sequence at 0, journal sequence at 8, flags at 16, version at 20 and payload length in 64-bit words at 22. Later node writes start with a checksum followed by a key-set header rather than repeating the entire node header. Validate sector offsets, checksums, key bounds, child level and parent ranges.

## Tree lookup and effective state

Tree IDs include extents 0, inodes 1, directory entries 2, extended attributes 3 and allocation 4. Each tree admits specific value tags. Internal pointers lead to child nodes; leaves hold typed records. Individual appended sets are sorted, but the effective node is a merge of its valid sets. Apply native overwrite, deletion and whiteout rules and ignore sets whose journal dependency is not durable under recovery rules. A reader cannot simply concatenate sets or choose the first match. Descend only through a validated root and consistent child ranges, detect cycles and cap depth and node sizes. Reconstruct the effective records before calculating allocation or directory contents.

## Extent pointers and logical mapping

An extent key offset represents the exclusive logical end in sectors; its size gives the sector length. The start is end minus size, provided subtraction does not underflow. The little-endian eight-byte extent pointer has type at bit 0, cached at 1, unused at 2, unwritten at 3, 44-bit sector offset at 4..47, device index at 48..55 and generation at 56..63. Decode the tagged extent-entry stream; pointer, checksum, stripe and rebalance records have different lengths and roles. For an ordinary uncompressed extent with logical end 112, size 8 and physical start 1000, logical sector 106 is at device sector 1002 (byte 513024). Do not apply this formula directly to compressed, shared, inline or unwritten records.

## Checksums, compression and redundancy

Checksum descriptors encode compressed and uncompressed sizes, logical offset, checksum algorithm, compression algorithm and, where present, nonce. The CRC32 descriptor occupies eight bytes, CRC64 sixteen bytes and CRC128 twenty-four bytes in the pinned definitions; their bit widths differ. Interpret encoded size conventions using the format accessors, not raw counts assumed to be bytes. A descriptor applies to subsequent associated pointers according to the extent stream rules. Verify the stored representation and decompress the admitted algorithm before extracting the logical interval. Cached replicas are not equivalent to durable required copies. Generation checks prevent stale references after bucket reuse. Multi-device erasure-coded stripes and encrypted data need their own validated reconstruction and authentication paths.

## Inodes, names and attributes

Inode values have multiple revisions. The v3 value begins with six little-endian 64-bit fields: journal sequence, hash seed, flags, sectors, logical byte size and version. The variable field area begins at byte 48 in the initial v3 layout; decode its start and field count through flags. Variable fields represent timestamps, ownership, link counts, generation, data options and subvolume information; they are not a fixed array of native C integers. Directory values begin with an eight-byte target inode, or two 32-bit subvolume identifiers for a subvolume entry, followed by type at offset 8 and name at 9. The tree position derives from parent identity and name hashing. Lookup must use the inode hash seed and selected algorithm, resolve collisions, apply snapshot visibility and compare the actual bounded name.

## Snapshot and subvolume records

A v6.12 snapshot value contains little-endian 32-bit flags at 0, parent at 4, two children at 8 and 12, subvolume at 16, tree ID at 20, depth at 24, three skip references at 28, 32 and 36, and 128-bit birth time at 40. Deleted and subvolume flags occupy bits 0 and 1. A subvolume value has flags at 0, snapshot ID at 4, root inode at 8, creation parent at 16, filesystem-path parent at 20 and 128-bit origin time at 24. These parent relationships are different. A snapshot-aware lookup considers ancestry and whiteouts, not merely the numerically highest snapshot ID. Shared extents and historical records remain allocated until all references are safely retired.

## Bucket allocation and relocation

The allocator manages buckets on each member device. For a physical sector p and bucket size b, bucket index is floor(p/b), and the in-bucket position is p modulo b. Check first_bucket, member size and generation. An allocation_v4 value begins with journal sequence at 0, flags at 8, generation at 12, oldest generation at 13, data type at 14, stripe redundancy at 15, dirty sectors at 16 and cached sectors at 20. Backpointers link physical ownership to logical tree records. A cleaner relocates live data and updates pointers, backpointers, usage and generation through ordered metadata transactions before reuse. Do not equate an unreferenced current-view block with a free bucket; snapshots, pending journal state, cache and replicas can all affect reuse.

## Journal and crash consistency

A journal set starts with checksum at 0, magic at 16, sequence at 24, format version at 32, flags at 36, payload word count at 40, read/write clocks at 44 and 46, and oldest dirty sequence at 48. Entries begin at 56; each entry header has a 16-bit payload word count, tree ID, tree level, type and three reserved bytes. Journal records include key updates, roots and sequence blacklist information. Recovery determines the valid sequence window, rejects invalid records, obtains consistent roots and applies admitted key updates in order. The clean superblock field can hold root and journal state; its presence is not permission to skip consistency validation. Checksummed metadata and flush ordering are separate requirements. No arbitrary repair or transaction replay should be performed on the source image.

## Implementation and qualification boundary

The independent provider uses Common V2: https://github.com/Infiltrator-Projects/Libraries/blob/main/docs/FILESYSTEM_COMMON_ABI_V2.md . Negotiate actual operation masks and media profiles. Distinguish unsupported, corrupt, I/O and stale-handle results. Require bounded host I/O, exclusive unmounted ownership and durable flush before mutation. Test Media and Defragmenter consume the same engine, not separate format parsers. Hosted and freestanding binaries, relocation, recovery, BOOT, kernel integration and packages require separate exact-source evidence. Current support belongs to the repository README and qualification records. The intended package paths are /System/Filesystems/ and /System/Resources/Documentation/; the reference is not an installation or release-status claim.

## Validation and source references

Use the pinned source at https://github.com/torvalds/linux/tree/v6.12/fs/bcachefs and its bcachefs_format.h, sb-members_format.h, extents_format.h, inode_format.h, dirent_format.h, snapshot_format.h, subvolume_format.h and alloc_background_format.h definitions. Follow the associated packing, journal replay, checksum, allocation and snapshot implementation for revision-specific algorithms. Compare clean single-device fixtures and then multi-device fixtures against version-matched native tools; test stale generation, conflicting superblocks, truncated typed records, malformed packed keys, whiteouts, shared extents and interrupted relocation. Exact checksum coverage/nonces, varint encoding, hash algorithms, feature upgrades, replay ordering and transactional writer invariants need further algorithm-level validation. This chapter is a research reference, not evidence of provider implementation or release qualification.

Early design reference: https://lkml.iu.edu/1805.1/01005.html .

Retained source: https://github.com/Infiltrator-Projects/Filesystems/blob/101026021d9088d80b7f0f472d9061f0e2c688a3/native/filesystems/bcachefs/linux/bcachefs_format.h (blob 5004f6ba99).
