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
    /// The per-source RSI request id allocator cannot advance without reusing an id.
    RsiRequestIdOverflow,
    /// A length-prefixed RSI payload field would overflow host arithmetic.
    RsiPayloadLengthOverflow,
    /// An RSI_WRITE_KEY request field mask contained bits not defined by PSD-005.
    UnknownRsiWriteKeyFieldMask {
        /// Full field mask.
        field_mask: u32,
        /// Unknown field mask bits.
        unknown: u32,
    },
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
