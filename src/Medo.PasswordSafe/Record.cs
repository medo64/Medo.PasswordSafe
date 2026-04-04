namespace Medo.Security.Cryptography.PasswordSafe;

using System;
using System.Diagnostics;

/// <summary>
/// Record field.
/// </summary>
[DebuggerDisplay("{RecordType}: {ToString(),nq}")]
public class Record : Field {

    /// <summary>
    /// Create a new instance.
    /// </summary>
    /// <param name="type">Record type.</param>
    public Record(RecordType type)
        : base() {
        RecordType = type;
        if (RecordType == RecordType.Autotype) { Text = @"\u\t\p\n"; } //to have default value
    }

    internal Record(RecordType type, byte[] rawData) : base() {
        if (type is < 0 or >= RecordType.EndOfEntry) { throw new ArgumentOutOfRangeException(nameof(type), "Type not supported."); }
        RecordType = type;
        RawData = rawData;
    }

    internal Record(RecordCollection owner, RecordType type)
        : this(type) {
        Owner = owner;
    }


    internal RecordCollection? Owner { get; set; }


    /// <summary>
    /// Gets field type.
    /// </summary>
    public RecordType RecordType { get; set; }

    /// <summary>
    /// Gets caption.
    /// Caption is not localized.
    /// </summary>
    public virtual string? Caption {
        get {
            return RecordType switch {
                RecordType.Uuid => "UUID",
                RecordType.Group => "Group",
                RecordType.Title => "Title",
                RecordType.UserName => "User name",
                RecordType.Notes => "Notes",
                RecordType.Password => "Password",
                RecordType.Url => "URL",
                RecordType.Autotype => "Auto-type",
                RecordType.PasswordHistory => "Password history",
                RecordType.PasswordPolicy => "Password policy",
                RecordType.RunCommand => "Run command",
                RecordType.EmailAddress => "Email address",
                RecordType.OwnSymbolsForPassword => "Own symbols for password",
                RecordType.PasswordPolicyName => "Password policy name",
                RecordType.CreditCardNumber => "Card number",
                RecordType.CreditCardExpiration => "Card expiration",
                RecordType.CreditCardVerificationValue => "Card verification code",
                RecordType.CreditCardPin => "Card pin",
                RecordType.QRCode => "QR code",
                RecordType.CreationTime => "Cration time",
                RecordType.PasswordModificationTime => "Password modification time",
                RecordType.LastAccessTime => "Last access time",
                RecordType.PasswordExpiryTime => "Password expiry time",
                RecordType.LastModificationTime => "Last modification time",
                RecordType.TwoFactorKey => "Two-factor key",
                _ => null,
            };
        }
        set {
            throw new NotSupportedException("Custom caption is not supported for this field type.");
        }
    }

    /// <summary>
    /// Gets/sets text data.
    /// Null will be returned if conversion cannot be performed.
    /// For unknown field types, conversion will always be attempted.
    /// </summary>
    public override string? Text {
        get { return base.Text; }
        set {
            if (RecordType == RecordType.Password) { //only for password change update history
                if ((Owner != null) && Owner.Contains(RecordType.PasswordHistory) && Owner.Contains(RecordType.Password)) {
                    var history = new PasswordHistoryCollection(Owner);
                    if (history.Enabled && (Text != null)) {
                        var time = Owner.Contains(RecordType.PasswordModificationTime) ? Owner[RecordType.PasswordModificationTime].Time : DateTime.UtcNow;
                        history.AddPasswordToHistory(time, Text); //save current password
                    }
                }
            }
            base.Text = value;
        }
    }


    /// <summary>
    /// Used to mark document as changed.
    /// </summary>
    protected override void MarkAsChanged() {
        Owner?.MarkAsChanged(RecordType);
    }

    /// <summary>
    /// Used to mark document as accessed.
    /// </summary>
    protected override void MarkAsAccessed() {
        Owner?.MarkAsAccessed(RecordType);
    }

    /// <summary>
    /// Gets if object is read-only.
    /// </summary>
    protected override bool IsReadOnly {
        get { return Owner?.IsReadOnly ?? false; }
    }

    /// <summary>
    /// Gets if object is sensitive.
    /// Sensitive fields should be shown to user hidden by default.
    /// </summary>
    public virtual bool IsSensitive {
        get {
            return RecordType switch {
                RecordType.Uuid => false,
                RecordType.Group => false,
                RecordType.Title => false,
                RecordType.UserName => false,
                RecordType.Notes => false,
                RecordType.Password => true,
                RecordType.Url => false,
                RecordType.Autotype => false,
                RecordType.PasswordHistory => false,
                RecordType.PasswordPolicy => false,
                RecordType.RunCommand => false,
                RecordType.EmailAddress => false,
                RecordType.OwnSymbolsForPassword => false,
                RecordType.PasswordPolicyName => false,
                RecordType.CreditCardNumber => false,
                RecordType.CreditCardExpiration => false,
                RecordType.CreditCardVerificationValue => false,
                RecordType.CreditCardPin => true,
                RecordType.QRCode => false,
                RecordType.CreationTime => false,
                RecordType.PasswordModificationTime => false,
                RecordType.LastAccessTime => false,
                RecordType.PasswordExpiryTime => false,
                RecordType.LastModificationTime => false,
                RecordType.TwoFactorKey => true,
                _ => false,
            };
        }
        set {
            throw new NotSupportedException("Custom sensitivity is not supported for this field type.");
        }
    }


    /// <summary>
    /// Gets underlying data type for field.
    /// </summary>
    protected override PasswordSafeFieldDataType DataType {
        get {
            return RecordType switch {
                RecordType.Uuid => PasswordSafeFieldDataType.Uuid,
                RecordType.Group => PasswordSafeFieldDataType.Text,
                RecordType.Title => PasswordSafeFieldDataType.Text,
                RecordType.UserName => PasswordSafeFieldDataType.Text,
                RecordType.Notes => PasswordSafeFieldDataType.Text,
                RecordType.Password => PasswordSafeFieldDataType.Text,
                RecordType.Url => PasswordSafeFieldDataType.Text,
                RecordType.Autotype => PasswordSafeFieldDataType.Text,
                RecordType.PasswordHistory => PasswordSafeFieldDataType.Text,
                RecordType.PasswordPolicy => PasswordSafeFieldDataType.Text,
                RecordType.RunCommand => PasswordSafeFieldDataType.Text,
                RecordType.EmailAddress => PasswordSafeFieldDataType.Text,
                RecordType.OwnSymbolsForPassword => PasswordSafeFieldDataType.Text,
                RecordType.PasswordPolicyName => PasswordSafeFieldDataType.Text,
                RecordType.CreditCardNumber => PasswordSafeFieldDataType.Text,
                RecordType.CreditCardExpiration => PasswordSafeFieldDataType.Text,
                RecordType.CreditCardVerificationValue => PasswordSafeFieldDataType.Text,
                RecordType.CreditCardPin => PasswordSafeFieldDataType.Text,
                RecordType.QRCode => PasswordSafeFieldDataType.Text,
                RecordType.CreationTime => PasswordSafeFieldDataType.Time,
                RecordType.PasswordModificationTime => PasswordSafeFieldDataType.Time,
                RecordType.LastAccessTime => PasswordSafeFieldDataType.Time,
                RecordType.PasswordExpiryTime => PasswordSafeFieldDataType.Time,
                RecordType.LastModificationTime => PasswordSafeFieldDataType.Time,
                RecordType.TwoFactorKey => PasswordSafeFieldDataType.Binary,
                _ => PasswordSafeFieldDataType.Unknown,
            };
        }
    }


    #region Clone

    /// <summary>
    /// Returns the exact copy of the record.
    /// </summary>
    public virtual Record Clone() {
        return new Record(RecordType, base.GetRawDataDirect());
    }

    #endregion

}
