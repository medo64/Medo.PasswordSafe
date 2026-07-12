namespace Medo.Security.Cryptography.PasswordSafe;

/// <summary>
/// Underlying data type enumeration used for data parsing.
/// </summary>
internal enum PasswordSafeFieldDataType {
    /// <summary>
    /// Unknown data type.
    /// </summary>
    Unknown,
    /// <summary>
    /// Version.
    /// </summary>
    Version,
    /// <summary>
    /// UUID.
    /// </summary>
    Uuid,
    /// <summary>
    /// Text.
    /// </summary>
    Text,
    /// <summary>
    /// Time.
    /// </summary>
    Time,
    /// <summary>
    /// Bytes.
    /// </summary>
    Binary,
}
