/// Canonical error type for the LCS semantic core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsError {
    /// UTF-8 decoding failed before semantic parsing.
    InvalidUtf8 {
        /// Logical input field.
        field: &'static str,
    },
    /// A string contained a forbidden null byte.
    NullByte {
        /// Logical input field.
        field: &'static str,
    },
    /// A string field that must be non-empty was empty.
    EmptyString {
        /// Logical input field.
        field: &'static str,
    },
    /// A registry path was empty.
    EmptyPath,
    /// A path contained a leading, consecutive, or otherwise empty component.
    EmptyPathComponent,
    /// A path ended in a separator.
    TrailingPathSeparator,
    /// A key-like name contained `/` or `\`.
    NameContainsSeparator {
        /// Logical input field.
        field: &'static str,
    },
    /// A string exceeded its configured byte limit.
    NameTooLong {
        /// Logical input field.
        field: &'static str,
        /// Actual UTF-8 byte length.
        len: usize,
        /// Maximum permitted UTF-8 byte length.
        max: usize,
    },
    /// A full registry path exceeded its configured byte limit.
    PathTooLong {
        /// Actual UTF-8 byte length.
        len: usize,
        /// Maximum permitted UTF-8 byte length.
        max: usize,
    },
    /// A path exceeded the configured key-depth limit.
    KeyDepthExceeded {
        /// Actual component count.
        depth: usize,
        /// Maximum permitted component count.
        max: usize,
    },
    /// A source attempted to register the reserved `CurrentUser` hive.
    ReservedHiveName,
    /// A caller supplied desired_access = 0.
    ZeroDesiredAccess,
    /// An access mask contained bits outside the PSD-005 valid mask.
    UnknownAccessBits(u32),
    /// `MAXIMUM_ALLOWED` appeared in an ACE mask.
    MaximumAllowedInAce(u32),
    /// An ACE mask mapped to bits outside registry concrete rights.
    AceMaskMapsOutsideRegistryRights(u32),
    /// A value write used an unknown registry value type.
    UnknownValueType(u32),
    /// `REG_TOMBSTONE` was used outside the explicit tombstone operation.
    TombstoneNotExplicit,
    /// A tombstone write carried non-empty data.
    TombstoneDataMustBeEmpty {
        /// Tombstone data length.
        len: usize,
    },
    /// A value payload exceeded the configured maximum size.
    ValueDataTooLarge {
        /// Actual payload length.
        len: usize,
        /// Maximum permitted payload length.
        max: usize,
    },
    /// A value write would exceed MaxLayersPerValue admission control.
    TooManyLayersPerValue {
        /// Distinct layers currently observed for the value.
        count: usize,
        /// Maximum permitted distinct layers for one value.
        max: usize,
    },
    /// A configuration value was outside its ratified range.
    InvalidConfigValue {
        /// Parameter name.
        parameter: &'static str,
        /// Received value.
        value: u32,
        /// Minimum accepted value.
        min: u32,
        /// Maximum accepted value.
        max: u32,
    },
    /// The global sequence counter cannot advance without overflowing.
    SequenceOverflow,
    /// A source returned a sequence number from the future.
    FutureSequence {
        /// Source-returned sequence number.
        sequence: u64,
        /// Current LCS next-sequence value.
        next_sequence: u64,
    },
    /// Two entries tied for the winning resolution tuple.
    DuplicateWinningSequenceTie {
        /// Winning layer precedence.
        precedence: u32,
        /// Winning sequence number.
        sequence: u64,
    },
    /// The layer table contained duplicate folded identities.
    DuplicateLayerIdentity,
    /// A resolution context did not contain the hardcoded base layer.
    MissingBaseLayer,
    /// The base layer entry was not canonical precedence 0 and enabled.
    InvalidBaseLayerProperties {
        /// Observed base-layer precedence.
        precedence: u32,
        /// Observed base-layer enabled flag.
        enabled: bool,
    },
    /// The in-memory layer table exceeded the configured layer cap.
    TooManyLayers {
        /// Effective layer count.
        count: usize,
        /// Maximum permitted effective layer count.
        max: usize,
    },
    /// A private-layer credential set exceeded the configured cap.
    TooManyPrivateLayers {
        /// Private layer count.
        count: usize,
        /// Maximum permitted private layer count.
        max: usize,
    },
    /// A private-layer credential set contained duplicate folded identities.
    DuplicatePrivateLayerIdentity,
    /// A hive table contained duplicate folded identities in one namespace.
    DuplicateHiveIdentity,
    /// A private hive credential set exceeded the configured scope GUID cap.
    TooManyScopeGuids {
        /// Scope GUID count.
        count: usize,
        /// Maximum permitted scope GUID count.
        max: usize,
    },
    /// A private hive credential set contained duplicate scope GUIDs.
    DuplicateScopeGuid,
    /// Source registration was attempted without SeTcbPrivilege.
    MissingTcbPrivilege,
    /// A source registration request contained no hives.
    ZeroHiveCount,
    /// A source registration request exceeded the configured hive cap.
    TooManyHives {
        /// Hive count.
        count: usize,
        /// Maximum permitted hive count.
        max: usize,
    },
    /// A new source registration would exceed the configured source cap.
    TooManyRegisteredSources {
        /// Registered source slot count.
        count: usize,
        /// Maximum permitted source slot count.
        max: usize,
    },
    /// A source registration hive contained unknown RSI_HIVE_* flags.
    UnknownHiveFlags {
        /// Full flags value.
        flags: u32,
        /// Unknown flag bits.
        unknown: u32,
    },
    /// A global source registration hive carried a non-zero scope GUID.
    GlobalHiveHasScopeGuid,
    /// A source registration hive root GUID was nil.
    NilHiveRootGuid,
    /// A source registration request reused a root GUID within the request.
    DuplicateHiveRootGuid,
    /// A registration collided with an existing reserved hive identity.
    HiveIdentityCollision,
    /// A Down source slot was resumed with stale hive identity data.
    StaleSourceHiveIdentity,
    /// A Down source slot was only partially or incorrectly resumed.
    PartialSourceResume,
    /// A key record or create request used nil as a key GUID.
    NilKeyGuid,
    /// A child key record or create request used nil as a parent GUID.
    NilParentGuid,
    /// A reg_create_key request contained unknown REG_OPTION_* bits.
    UnknownCreateFlags {
        /// Full flags value.
        flags: u32,
        /// Unknown flag bits.
        unknown: u32,
    },
    /// A non-volatile child was requested under a volatile parent key.
    NonVolatileChildUnderVolatile,
    /// Key creation was attempted without KEY_CREATE_SUB_KEY on the parent.
    MissingKeyCreateSubKey,
    /// Symlink creation was attempted without KEY_CREATE_LINK on the parent.
    MissingKeyCreateLink,
    /// Symlink creation was attempted without TCB privilege or Administrator membership.
    MissingSymlinkCreationAuthority,
    /// A layer-targeted mutation was attempted without the required target key fd right.
    MissingTargetKeyFdAccess {
        /// Concrete registry access right required on the target key fd.
        required: u32,
    },
    /// A layer-targeted mutation was attempted without KEY_SET_VALUE on the layer metadata key.
    MissingLayerMetadataSetValue,
    /// Establishing or elevating a layer above precedence 0 was attempted without SeTcbPrivilege.
    MissingLayerPrecedenceTcb,
    /// A symlink key had no effective default value to interpret as REG_LINK.
    SymlinkDefaultValueMissing,
    /// A symlink key's effective default value was not REG_LINK.
    SymlinkDefaultNotRegLink(u32),
    /// Following another symlink would exceed SymlinkDepthLimit.
    SymlinkDepthExceeded {
        /// Attempted follow depth.
        depth: usize,
        /// Maximum permitted follow depth.
        max: usize,
    },
    /// A source response carried a status outside the defined RSI vocabulary.
    UnknownRsiStatus(u32),
    /// An RSI message was shorter than the mandatory fixed header or status payload.
    RsiMessageTooShort {
        /// Actual frame length.
        len: usize,
        /// Minimum required length.
        min: usize,
    },
    /// An RSI message's declared total length did not match the copied frame length.
    RsiMessageLengthMismatch {
        /// Header-declared total length.
        total_len: u32,
        /// Actual frame length copied from or to userspace.
        actual_len: usize,
    },
    /// An RSI op code was outside the PSD-005 operation vocabulary.
    UnknownRsiOpcode(u16),
    /// A response request_id did not match the retained request record.
    RsiRequestIdMismatch {
        /// Retained request id.
        expected: u64,
        /// Response-provided request id.
        actual: u64,
    },
    /// A response op code did not equal request op_code | RSI_RESPONSE_BIT.
    RsiResponseOpcodeMismatch {
        /// Expected response op code.
        expected: u16,
        /// Actual response op code.
        actual: u16,
    },
    /// A validator for status-only responses was used for an operation with a success payload.
    RsiResponseRequiresPayloadParser(u16),
    /// A status-only RSI response carried bytes after the status field.
    RsiUnexpectedResponsePayload {
        /// Request op code answered by the response.
        op_code: u16,
        /// Bytes following the status field.
        extra_len: usize,
    },
    /// An operation-specific response parser was used for the wrong request op code.
    RsiResponsePayloadParserMismatch {
        /// Parser's expected request op code.
        expected: u16,
        /// Retained request op code supplied to the parser.
        actual: u16,
    },
    /// A success-response payload parser received a non-success status.
    RsiResponseStatusNotOk(u32),
    /// A path-entry response target_type was outside the RSI vocabulary.
    InvalidRsiPathTargetType(u8),
    /// A HIDDEN path-entry response target carried a non-zero GUID.
    RsiHiddenPathTargetGuidNotZero,
    /// A GUID path target in a path response had no matching metadata entry.
    RsiPathMetadataMissing {
        /// GUID referenced by a returned path entry.
        guid: [u8; 16],
    },
    /// A path response metadata block repeated the same key GUID.
    RsiPathMetadataDuplicate {
        /// Duplicated metadata GUID.
        guid: [u8; 16],
    },
    /// A path response metadata entry did not correspond to any GUID path target.
    RsiPathMetadataUnreferenced {
        /// Metadata GUID not referenced by any path entry.
        guid: [u8; 16],
    },
    /// A path response metadata block used nil as a key GUID.
    RsiPathMetadataNilGuid,
    /// A source-returned security descriptor was malformed or unusable for AccessCheck.
    MalformedSecurityDescriptor {
        /// Logical source-response field.
        field: &'static str,
    },
    /// RSI_DELETE_LAYER returned nil as an orphaned key GUID.
    RsiDeleteLayerOrphanedGuidNil,
    /// RSI_DELETE_LAYER returned the same orphaned key GUID more than once.
    RsiDeleteLayerOrphanedGuidDuplicate {
        /// Duplicated orphaned key GUID.
        guid: [u8; 16],
    },
    /// The per-source RSI request id allocator cannot advance without reusing an id.
    RsiRequestIdOverflow,
    /// An output buffer was too small for the RSI request frame being constructed.
    RsiFrameBufferTooSmall {
        /// Caller-provided output buffer length.
        len: usize,
        /// Required RSI frame length.
        required: usize,
    },
    /// A backup record frame was shorter than the common 6-byte header.
    BackupRecordHeaderTooShort {
        /// Actual frame length.
        len: usize,
    },
    /// An output buffer was too small for the backup record header being constructed.
    BackupRecordHeaderBufferTooSmall {
        /// Caller-provided output buffer length.
        len: usize,
    },
    /// A backup record declared a length smaller than the common header.
    BackupRecordTooSmall {
        /// Header-declared record length.
        record_len: u32,
    },
    /// A backup record's declared total length did not match the copied frame length.
    BackupRecordLengthMismatch {
        /// Header-declared record length.
        record_len: u32,
        /// Actual frame length copied from userspace/source stream.
        actual_len: usize,
    },
    /// A backup record parser was used for the wrong record type.
    BackupRecordKindMismatch {
        /// Expected record type code.
        expected: u16,
        /// Actual record type code.
        actual: u16,
    },
    /// A complete backup record writer was given an output buffer that was too small.
    BackupRecordFrameBufferTooSmall {
        /// Caller-provided output buffer length.
        len: usize,
        /// Required backup record frame length.
        required: usize,
    },
    /// A backup payload field would overflow host or wire length arithmetic.
    BackupPayloadLengthOverflow,
    /// A backup record payload ended before a mandatory field was complete.
    BackupPayloadTooShort {
        /// Actual payload length.
        len: usize,
        /// Minimum payload length needed for the parsed fields.
        min: usize,
    },
    /// A backup record payload carried bytes after its exact defined payload.
    BackupUnexpectedPayload {
        /// Record type being parsed.
        record_type: u16,
        /// Bytes left after the exact payload parser finished.
        extra_len: usize,
    },
    /// A backup HEADER magic field did not match the PSD-005 magic bytes.
    InvalidBackupMagic {
        /// Actual eight-byte magic field.
        actual: [u8; 8],
    },
    /// A backup HEADER requires a newer reader than this parser supports.
    UnsupportedBackupMinReaderVersion {
        /// Minimum reader version declared by the stream.
        min_reader_version: u32,
        /// Reader version supported by the caller.
        supported_version: u32,
    },
    /// A backup record carried a malformed binary SID field.
    MalformedBackupSid {
        /// Logical backup field.
        field: &'static str,
    },
    /// A backup KEY record contained unknown flag bits.
    UnknownBackupKeyFlags {
        /// Full flags value.
        flags: u32,
        /// Unknown flag bits.
        unknown: u32,
    },
    /// A backup TRAILER record count cannot include both HEADER and TRAILER.
    BackupRecordCountTooSmall {
        /// TRAILER-declared record count.
        record_count: u64,
    },
    /// A backup stream ended before any HEADER record was observed.
    BackupStreamMissingHeader,
    /// The first backup stream record was not HEADER.
    BackupStreamFirstRecordNotHeader {
        /// Actual first record type code.
        actual: u16,
    },
    /// A backup stream contained HEADER after record index zero.
    BackupStreamDuplicateHeader {
        /// Zero-based record index of the invalid HEADER.
        index: u64,
    },
    /// A backup stream contained a record after TRAILER.
    BackupStreamRecordAfterTrailer {
        /// Zero-based record index of the invalid record.
        index: u64,
        /// Invalid record type code.
        record_type: u16,
    },
    /// A backup stream ended without a TRAILER record.
    BackupStreamMissingTrailer,
    /// A backup stream's TRAILER RecordCount did not match observed records.
    BackupStreamRecordCountMismatch {
        /// TRAILER-declared record count.
        declared: u64,
        /// Number of records observed by LCS.
        observed: u64,
    },
    /// A backup stream checksum did not match the TRAILER checksum.
    BackupStreamChecksumMismatch {
        /// TRAILER-declared checksum.
        declared: [u8; 32],
        /// SHA-256 digest computed by the caller over the specified stream range.
        computed: [u8; 32],
    },
    /// The backup stream record counter cannot advance without overflowing.
    BackupStreamRecordCountOverflow,
    /// A backup stream contained duplicate folded LAYER manifest identities.
    DuplicateBackupLayerManifest,
    /// A backup layer-qualified record referenced a layer missing from the manifest.
    MissingBackupLayerManifest,
    /// A backup restore stream did not contain a KEY for HEADER.RootGUID.
    BackupRestoreRootKeyMissing,
    /// A restore root write was planned from a KEY other than HEADER.RootGUID.
    BackupRestoreRootKeyGuidMismatch {
        /// HEADER.RootGUID expected by the restore stream.
        expected: [u8; 16],
        /// KEY GUID supplied as the root KEY.
        actual: [u8; 16],
    },
    /// Restore tried to create the already-existing target root key as a non-root key.
    BackupRestoreRootKeyCreateNotAllowed {
        /// Root KEY GUID supplied to the non-root create planner.
        guid: [u8; 16],
    },
    /// A backup restore stream contained more than one KEY for HEADER.RootGUID.
    BackupRestoreRootKeyDuplicate,
    /// A backup root KEY immutable flag did not match the restore target key.
    BackupRestoreRootImmutableFlagsConflict {
        /// Backup root volatile flag.
        backup_volatile: bool,
        /// Restore target volatile flag.
        target_volatile: bool,
        /// Backup root symlink flag.
        backup_symlink: bool,
        /// Restore target symlink flag.
        target_symlink: bool,
    },
    /// A backup restore stream contained duplicate remapped key GUIDs.
    DuplicateBackupKeyGuid {
        /// Duplicated remapped key GUID.
        guid: [u8; 16],
    },
    /// A non-root backup GUID collided with an existing key outside the replaced subtree.
    BackupGuidCollision {
        /// Colliding remapped key GUID.
        guid: [u8; 16],
    },
    /// A restore PATH_ENTRY parent GUID did not refer to the remapped subtree.
    BackupRestoreParentGuidOutsideSubtree {
        /// Remapped parent GUID.
        parent_guid: [u8; 16],
    },
    /// A non-root KEY section did not contain a GUID-bearing create anchor for that key.
    BackupRestoreKeyCreateAnchorMissing {
        /// Non-root key GUID being restored.
        key_guid: [u8; 16],
    },
    /// A PATH_ENTRY in a non-root KEY section did not target that section's KEY.
    BackupRestoreKeyCreateAnchorTargetMismatch {
        /// Non-root key GUID being restored.
        key_guid: [u8; 16],
        /// Remapped child GUID, or nil for HIDDEN.
        child_guid: [u8; 16],
    },
    /// A restore VALUE or BLANKET_TOMBSTONE KeyGUID did not refer to the remapped subtree.
    BackupRestoreKeyGuidOutsideSubtree {
        /// Remapped key GUID.
        key_guid: [u8; 16],
    },
    /// A length-prefixed RSI payload field would overflow host arithmetic.
    RsiPayloadLengthOverflow,
    /// An RSI_WRITE_KEY request field mask contained bits not defined by PSD-005.
    UnknownRsiWriteKeyFieldMask {
        /// Full field mask.
        field_mask: u32,
        /// Unknown field mask bits.
        unknown: u32,
    },
    /// An RSI_BEGIN_TRANSACTION request mode was outside the PSD-005 vocabulary.
    UnknownRsiTransactionMode(u32),
    /// An ioctl command number is outside the PSD-005 registry ioctl vocabulary.
    UnknownRegistryIoctl(u8),
    /// A security descriptor component selector was zero.
    ZeroSecurityInfo,
    /// A security descriptor component selector contained bits PSD-005 does not define for LCS.
    UnknownSecurityInfoFlags {
        /// Full selector value.
        flags: u32,
        /// Unknown selector bits.
        unknown: u32,
    },
    /// A variable-size output buffer had non-zero length but no pointer.
    MissingOutputBufferPointer {
        /// Requested output buffer length.
        len: usize,
    },
    /// A computed userspace output payload length overflowed host arithmetic.
    OutputSizeOverflow,
    /// A volatile per-hive generation counter cannot advance without overflowing.
    HiveGenerationOverflow,
    /// A key fd's resolved path and ancestor GUID metadata were inconsistent.
    InvalidFdAncestry,
    /// A namespace mutation was attempted on a hive root key.
    HiveRootKeyOperation,
    /// A namespace mutation was attempted through an already-orphaned key fd.
    OrphanedKeyNamespaceOperation,
    /// A key delete was attempted while visible children still exist.
    KeyHasVisibleChildren {
        /// Visible child count observed before delete.
        count: u32,
    },
    /// A REG_IOC_NOTIFY filter contained bits PSD-005 does not define.
    UnknownNotifyFilterFlags {
        /// Full filter value.
        flags: u32,
        /// Unknown filter bits.
        unknown: u32,
    },
    /// A one-byte boolean ABI field was not 0 or 1.
    InvalidBooleanFlag {
        /// Logical input field.
        field: &'static str,
        /// Received byte value.
        value: u8,
    },
    /// A reserved ABI pad field was non-zero.
    NonZeroReservedBytes {
        /// Logical input field.
        field: &'static str,
    },
    /// A new watch was armed on an already-orphaned key fd.
    OrphanedWatchArm,
    /// An internal or source-derived watch event type was outside PSD-005's vocabulary.
    UnknownWatchEventType(u32),
    /// An event type whose name field must be empty carried a name.
    WatchNoNameEventCarriedName {
        /// Watch event type.
        event_type: u32,
    },
    /// A direct watch event was asked to carry subtree path components.
    DirectWatchEventHasPath,
    /// A queued watch event length was smaller than the mandatory header.
    InvalidWatchEventLength(u32),
    /// A read buffer was too small to hold the first pending watch event.
    WatchReadBufferTooSmall {
        /// Caller-supplied read buffer length.
        buffer_len: usize,
        /// First queued event length.
        first_event_len: usize,
    },
    /// A watch queue limit was zero.
    InvalidWatchQueueLimit,
    /// A watch queue snapshot was internally inconsistent.
    InvalidWatchQueueState,
    /// A transaction watch burst limit was zero.
    InvalidTransactionWatchBurstLimit,
    /// Captured watch dispatch ancestry was empty or had mismatched GUID/path lengths.
    InvalidWatchAncestry,
    /// The changed key GUID was not the last GUID in the captured mutation ancestry.
    WatchChangedKeyNotLastAncestor,
    /// A maintenance operation targeted a hive whose source is currently unavailable.
    HiveSourceUnavailable,
    /// Transaction ID zero is reserved for "no transaction" in RSI.
    InvalidTransactionId,
    /// The monotonic transaction ID allocator cannot advance without overflowing.
    TransactionIdOverflow,
}

/// Standard result type for the LCS semantic core.
pub type LcsResult<T> = core::result::Result<T, LcsError>;
