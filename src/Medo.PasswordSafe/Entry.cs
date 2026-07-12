namespace Medo.Security.Cryptography.PasswordSafe;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

/// <summary>
/// Entry.
/// </summary>
public class Entry {

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public Entry()
        : this([
                new Record(RecordType.Uuid, Guid.NewGuid().ToByteArray()),
                new Record(RecordType.Title, []),
                new Record(RecordType.Password, [])
        ]) {
    }

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="title">Title.</param>
    public Entry(string title) : this() {
        Title = title;
    }

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="group">Group.</param>
    /// <param name="title">Title.</param>
    public Entry(GroupPath group, string title) : this() {
        Group = group;
        Title = title;
    }


    internal Entry(ICollection<Record> records) {
        Records = new RecordCollection(this, records);
    }


    internal EntryCollection? Owner { get; set; }

    /// <summary>
    /// Used to mark document as changed.
    /// </summary>
    protected void MarkAsChanged() {
        Owner?.MarkAsChanged();
    }


    /// <summary>
    /// Gets/sets UUID.
    /// </summary>
    public Guid Uuid {
        get { return Records.Contains(RecordType.Uuid) ? Records[RecordType.Uuid].Uuid : Guid.Empty; }
        set { Records[RecordType.Uuid].Uuid = value; }
    }

    /// <summary>
    /// Gets/sets group.
    /// </summary>
    public GroupPath Group {
        get { return Records.Contains(RecordType.Group) ? Records[RecordType.Group].Text ?? "" : ""; }
        set { Records[RecordType.Group].Text = value; }
    }


    /// <summary>
    /// Gets/sets title.
    /// </summary>
    public string Title {
        get { return Records.Contains(RecordType.Title) ? Records[RecordType.Title].Text ?? "" : ""; }
        set { Records[RecordType.Title].Text = value; }
    }

    /// <summary>
    /// Gets/sets user name.
    /// </summary>
    public string UserName {
        get { return Records.Contains(RecordType.UserName) ? Records[RecordType.UserName].Text ?? "" : ""; }
        set { Records[RecordType.UserName].Text = value; }
    }

    /// <summary>
    /// Gets/sets notes.
    /// </summary>
    public string Notes {
        get { return Records.Contains(RecordType.Notes) ? Records[RecordType.Notes].Text ?? "" : ""; }
        set { Records[RecordType.Notes].Text = value; }
    }

    /// <summary>
    /// Gets/sets password.
    /// </summary>
    public string Password {
        get { return Records.Contains(RecordType.Password) ? Records[RecordType.Password].Text ?? "" : ""; }
        set { Records[RecordType.Password].Text = value; }
    }


    /// <summary>
    /// Gets/sets creation time.
    /// </summary>
    public DateTime CreationTime {
        get { return Records.Contains(RecordType.CreationTime) ? Records[RecordType.CreationTime].Time : DateTime.MinValue; }
        set { Records[RecordType.CreationTime].Time = value; }
    }

    /// <summary>
    /// Gets/sets password modification time.
    /// </summary>
    public DateTime PasswordModificationTime {
        get { return Records.Contains(RecordType.PasswordModificationTime) ? Records[RecordType.PasswordModificationTime].Time : DateTime.MinValue; }
        set { Records[RecordType.PasswordModificationTime].Time = value; }
    }

    /// <summary>
    /// Gets/sets last access time.
    /// </summary>
    public DateTime LastAccessTime {
        get { return Records.Contains(RecordType.LastAccessTime) ? Records[RecordType.LastAccessTime].Time : DateTime.MinValue; }
        set { Records[RecordType.LastAccessTime].Time = value; }
    }

    /// <summary>
    /// Gets/sets password expiry time.
    /// </summary>
    public DateTime PasswordExpiryTime {
        get { return Records.Contains(RecordType.PasswordExpiryTime) ? Records[RecordType.PasswordExpiryTime].Time : DateTime.MinValue; }
        set { Records[RecordType.PasswordExpiryTime].Time = value; }
    }

    /// <summary>
    /// Gets/sets last modification time.
    /// </summary>
    public DateTime LastModificationTime {
        get { return Records.Contains(RecordType.LastModificationTime) ? Records[RecordType.LastModificationTime].Time : DateTime.MinValue; }
        set { Records[RecordType.LastModificationTime].Time = value; }
    }


    /// <summary>
    /// Gets/sets URL.
    /// </summary>
#pragma warning disable CA1056 // URI-like properties should not be strings
    public string Url {
#pragma warning restore CA1056 // URI-like properties should not be strings
        get { return Records.Contains(RecordType.Url) ? Records[RecordType.Url].Text ?? "" : ""; }
        set { Records[RecordType.Url].Text = value; }
    }


    /// <summary>
    /// Gets/sets e-mail address.
    /// </summary>
    public string Email {
        get { return Records.Contains(RecordType.EmailAddress) ? Records[RecordType.EmailAddress].Text ?? "" : ""; }
        set { Records[RecordType.EmailAddress].Text = value; }
    }


    /// <summary>
    /// Gets/sets two factor key.
    /// </summary>
    [Obsolete("Use GetTwoFactorKey/SetTwoFactorKey")]
#pragma warning disable CA1819 // Properties should not return arrays
    public byte[] TwoFactorKey {
#pragma warning restore CA1819 // Properties should not return arrays
        get { return GetTwoFactorKey(); }
        set { SetTwoFactorKey(value); }
    }

    /// <summary>
    /// Gets/sets two factor key.
    /// </summary>
    public byte[] GetTwoFactorKey() {
        return Records.Contains(RecordType.TwoFactorKey)
               ? Records[RecordType.TwoFactorKey].GetBytes()
               : [];
    }

    /// <summary>
    /// Sets two factor key.
    /// </summary>
    public void SetTwoFactorKey(byte[] bytes) {
        Records[RecordType.TwoFactorKey].SetBytes(bytes);
    }


    /// <summary>
    /// Gets/sets credit card number.
    /// Number should consist of digits and spaces.
    /// </summary>
    public string CreditCardNumber {
        get { return Records.Contains(RecordType.CreditCardNumber) ? Records[RecordType.CreditCardNumber].Text ?? "" : ""; }
        set { Records[RecordType.CreditCardNumber].Text = value; }
    }

    /// <summary>
    /// Gets/sets credit card expiration.
    /// Format should be MM/YY, where MM is 01-12, and YY 00-99.
    /// </summary>
    public string CreditCardExpiration {
        get { return Records.Contains(RecordType.CreditCardExpiration) ? Records[RecordType.CreditCardExpiration].Text ?? "" : ""; }
        set { Records[RecordType.CreditCardExpiration].Text = value; }
    }

    /// <summary>
    /// Gets/sets credit card verification value.
    /// CVV (CVV2) is three or four digits.
    /// </summary>
    public string CreditCardVerificationValue {
        get { return Records.Contains(RecordType.CreditCardVerificationValue) ? Records[RecordType.CreditCardVerificationValue].Text ?? "" : ""; }
        set { Records[RecordType.CreditCardVerificationValue].Text = value; }
    }

    /// <summary>
    /// Gets/sets credit card PIN.
    /// PIN is four to twelve digits long (ISO-9564).
    /// </summary>
    public string CreditCardPin {
        get { return Records.Contains(RecordType.CreditCardPin) ? Records[RecordType.CreditCardPin].Text ?? "" : ""; }
        set { Records[RecordType.CreditCardPin].Text = value; }
    }

    /// <summary>
    /// Gets/sets UTF-8 encoded text used for QR code generation.
    /// </summary>
    public string QRCode {
        get { return Records.Contains(RecordType.QRCode) ? Records[RecordType.QRCode].Text ?? "" : ""; }
        set { Records[RecordType.QRCode].Text = value; }
    }


    /// <summary>
    /// Gets/sets auto-type text.
    /// </summary>
    public string Autotype {
        get { return Records.Contains(RecordType.Autotype) ? Records[RecordType.Autotype].Text ?? "" : ""; }
        set { Records[RecordType.Autotype].Text = value; }
    }

    /// <summary>
    /// Return auto-type tokens with textual fields filled in. Command fields, e.g. Wait, are not filled.
    /// Following commands are possible:
    /// * TwoFactorCode: 6-digit code for two-factor authentication.
    /// * Delay: Delay between characters in milliseconds.
    /// * Wait: Pause in milliseconds.
    /// * Legacy: Switches processing to legacy mode.
    /// </summary>
    public IEnumerable<AutotypeToken> AutotypeTokens {
        get { return AutotypeToken.GetAutotypeTokens(Autotype, this); }
    }


    /// <summary>
    /// Gets password history.
    /// </summary>
    public PasswordHistoryCollection PasswordHistory {
        get { return new PasswordHistoryCollection(Records); }
    }


    /// <summary>
    /// Gets password policy.
    /// </summary>
    public PasswordPolicy PasswordPolicy {
        get { return new PasswordPolicy(Records); }
    }

    /// <summary>
    /// Gets password policy name.
    /// </summary>
    public string PasswordPolicyName {
        get { return Records.Contains(RecordType.PasswordPolicyName) ? Records[RecordType.PasswordPolicyName].Text ?? "" : ""; }
        set { Records[RecordType.PasswordPolicyName].Text = value; }
    }


    /// <summary>
    /// Gets list of records.
    /// </summary>
    public RecordCollection Records { get; }


    /// <summary>
    /// Returns a string representation of an object.
    /// </summary>
    public override string ToString() {
        return Records.Contains(RecordType.Title) ? Records[RecordType.Title].Text ?? "" : "";
    }


    #region ICollection extra

    /// <summary>
    /// Gets field based on a type.
    /// If multiple elements exist with the same field type, the first one is returned.
    /// If type does not exist, it is created.
    /// </summary>
    /// <param name="type">Record type.</param>
    public Record this[RecordType type] {
        get { return Records[type]; }
        [Obsolete("Use Remove(type) instead.", error: true)]
        set { }
    }

    /// <summary>
    /// Removes the item from the collection.
    /// If multiple elements exist with the same field type, the first one is returned.
    /// </summary>
    /// <param name="type">Record type.</param>
    public bool Remove(RecordType type) {
        return Records.Remove(type);
    }

    #endregion


    #region Clone

    /// <summary>
    /// Returns the exact copy of the entry.
    /// </summary>
    public Entry Clone() {
        var records = new List<Record>();
        foreach (var record in Records) {
            records.Add(record.Clone());
        }
        return new Entry(records);
    }

    #endregion


    #region Export/Import

    /// <summary>
    /// Exports entry to a JSON object.
    /// </summary>
    public string ExportToJson() {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream);

        writer.WriteStartObject();
        writer.WritePropertyName("records");
        writer.WriteStartArray();

        foreach (var record in Records) {
            writer.WriteStartObject();
            writer.WriteString("caption", record.Caption);
            writer.WriteString("type", record.RecordType.ToString());
            switch (record.DataType) {
                case PasswordSafeFieldDataType.Unknown:
                    writer.WriteString("binary", Convert.ToBase64String(record.RawData));
                    break;
                case PasswordSafeFieldDataType.Version:
                    writer.WriteString("version", record.Version.ToString(CultureInfo.InvariantCulture));
                    break;
                case PasswordSafeFieldDataType.Uuid:
                    writer.WriteString("uuid", record.Uuid.ToString());
                    break;
                case PasswordSafeFieldDataType.Text:
                    writer.WriteString("text", record.Text);
                    break;
                case PasswordSafeFieldDataType.Time:
                    writer.WriteString("time", record.Time.ToString("O", CultureInfo.InvariantCulture));
                    break;
                case PasswordSafeFieldDataType.Binary:
                    writer.WriteString("binary", Convert.ToBase64String(record.RawData));
                    break;
                default:
                    writer.WriteString("binary", Convert.ToBase64String(record.RawData));
                    break;
            }
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();

        return UTF8Encoding.UTF8.GetString(stream.ToArray());
    }

    /// <summary>
    /// Imports entry from a JSON object.
    /// </summary>
    public static Entry ImportFromJson(string jsonText) {
        var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(jsonText));

        var records = new List<Record>();

        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) { return new Entry(records); }
        while (reader.Read()) {
            if (reader.TokenType == JsonTokenType.PropertyName) {
                var propName = reader.GetString();
                if (propName == "records") {
                    if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray) { continue; }

                    while (reader.Read()) {
                        if (reader.TokenType == JsonTokenType.EndArray) { break; }
                        if (reader.TokenType != JsonTokenType.StartObject) { continue; }

                        RecordType? recordType = null;
                        string? text = null;
                        string? uuid = null;
                        string? time = null;
                        string? version = null;
                        string? binaryB64 = null;

                        while (reader.Read()) {
                            if (reader.TokenType == JsonTokenType.EndObject) { break; }
                            if (reader.TokenType != JsonTokenType.PropertyName) { continue; }

                            var name = reader.GetString();
                            if (!reader.Read()) { break; }

                            switch (name) {
                                case "type":
                                    if (reader.TokenType == JsonTokenType.String) {
                                        var recType = reader.GetString();
                                        if (!string.IsNullOrEmpty(recType) && Enum.TryParse<RecordType>(recType, out var rt)) { recordType = rt; }
                                    }
                                    break;
                                case "text":
                                    if (reader.TokenType == JsonTokenType.String) { text = reader.GetString(); }
                                    break;
                                case "uuid":
                                    if (reader.TokenType == JsonTokenType.String) { uuid = reader.GetString(); }
                                    break;
                                case "time":
                                    if (reader.TokenType == JsonTokenType.String) { time = reader.GetString(); }
                                    break;
                                case "version":
                                    if (reader.TokenType == JsonTokenType.String) { version = reader.GetString(); }
                                    break;
                                case "binary":
                                    if (reader.TokenType == JsonTokenType.String) { binaryB64 = reader.GetString(); }
                                    break;
                                default:
                                    binaryB64 = reader.GetString();
                                    break;
                            }
                        }

                        if (recordType.HasValue) {
                            var record = new Record(recordType.Value);

                            switch (record.DataType) {
                                case PasswordSafeFieldDataType.Version:
                                    if (int.TryParse(version, NumberStyles.Integer, CultureInfo.InvariantCulture, out var versionValue)) {
                                        record.Version = versionValue;
                                    } else {
                                        throw new InvalidDataException("Cannot convert record to version.");
                                    }
                                    break;
                                case PasswordSafeFieldDataType.Uuid:
                                    if (Guid.TryParse(uuid, out var uuidValue)) {
                                        record.Uuid = uuidValue;
                                    } else {
                                        throw new InvalidDataException("Cannot convert record to UUID.");
                                    }
                                    break;
                                case PasswordSafeFieldDataType.Text:
                                    record.Text = text;
                                    break;
                                case PasswordSafeFieldDataType.Time:
                                    if (DateTime.TryParse(time, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var timeValue)) {
                                        record.Time = timeValue;
                                    } else {
                                        throw new InvalidDataException("Cannot convert record to Time.");
                                    }
                                    break;
                                case PasswordSafeFieldDataType.Binary:
                                    if (binaryB64 != null) {
                                        var binaryBuffer = new byte[binaryB64.Length];
#if NET10_0_OR_GREATER
                                        if (Convert.TryFromBase64String(binaryB64, binaryBuffer, out var bytesInBuffer)) {
                                            var data = new byte[bytesInBuffer];
                                            Buffer.BlockCopy(binaryBuffer, 0, data, 0, data.Length);
                                            record.SetBytes(data);
                                        } else {
                                            throw new InvalidDataException("Cannot find binary.");
                                        }
#else
                                        try {
                                            record.SetBytes(Convert.FromBase64String(binaryB64));
                                        } catch (FormatException) {
                                            throw new InvalidDataException("Cannot find binary.");
                                        }
#endif
                                    } else {
                                        throw new InvalidDataException("Cannot decode base64 binary.");
                                    }
                                    break;
                                case PasswordSafeFieldDataType.Unknown:
                                default:  // try auto-detect
                                    if ((version != null) && int.TryParse(version, NumberStyles.Integer, CultureInfo.InvariantCulture, out var versionValue2)) {
                                        record.Version = versionValue2;
                                    } else if ((uuid != null) && Guid.TryParse(uuid, out var uuidValue2)) {
                                        record.Uuid = uuidValue2;
                                    } else if ((time != null) && DateTime.TryParse(time, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var timeValue2)) {
                                        record.Time = timeValue2;
                                    } else if (binaryB64 != null) {
#if NET10_0_OR_GREATER
                                        var binaryBuffer2 = new byte[binaryB64.Length];
                                        if (Convert.TryFromBase64String(binaryB64, binaryBuffer2, out var bytesInBuffer)) {
                                            var data = new byte[bytesInBuffer];
                                            Buffer.BlockCopy(binaryBuffer2, 0, data, 0, data.Length);
                                            record.SetBytes(data);
                                        } else {
                                            throw new InvalidDataException("Cannot decode base64 binary.");
                                        }
#else
                                        try {
                                            record.SetBytes(Convert.FromBase64String(binaryB64));
                                        } catch (FormatException) {
                                            throw new InvalidDataException("Cannot find binary.");
                                        }
#endif
                                    } else {
                                        record.Text = text;
                                    }
                                    break;
                            }

                            records.Add(record);
                        }
                    }
                }
            } else if (reader.TokenType == JsonTokenType.EndObject) {
                break;
            }
        }

        return new Entry(records);

    }

    #endregion Export/Import

}
