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
}

/// Standard result type for the LCS semantic core.
pub type LcsResult<T> = core::result::Result<T, LcsError>;
