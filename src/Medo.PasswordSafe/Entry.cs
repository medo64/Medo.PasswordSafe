namespace Medo.Security.Cryptography.PasswordSafe;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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
        writer.WriteString("kind", "PWSafe3.Entry");
        writer.WritePropertyName("records");
        writer.WriteStartArray();

        foreach (var record in Records) {
            writer.WriteStartObject();
            writer.WriteString("type", record.RecordType.ToString());
            switch (record.DataType) {
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
                case PasswordSafeFieldDataType.Unknown:
                default:
                    if (record is CustomTextRecord customTextRecord) {
                        writer.WriteString("caption", record.Caption);
                        writer.WriteString("text", customTextRecord.Text);
                        if (customTextRecord.IsSensitive) {
                            writer.WriteBoolean("isSensitive", customTextRecord.IsSensitive);
                        }
                    } else {
                        writer.WriteString("binary", Convert.ToBase64String(record.RawData));
                    }
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
    /// Returns imported entry based on JSON object text.
    /// </summary>
    /// <param name="jsonText">JSON object.</param>
    public static Entry ImportFromJson(string jsonText) {
        (var entry, var exceptionText) = ImportFromJsonInt(jsonText);
        if (entry != null) {
            return entry;
        } else {
            throw new InvalidDataException(exceptionText ?? "Unknown error.");
        }
    }

    /// <summary>
    /// Returns true if entry based on JSON object text could be parsed.
    /// </summary>
    /// <param name="jsonText">JSON object.</param>
    /// <param name="entry">Output entry.</param>
#if NET8_0_OR_GREATER
    public static bool TryImportFromJson(string jsonText, [NotNullWhen(true)] out Entry? entry) {
#else
    public static bool TryImportFromJson(string jsonText, out Entry? entry) {
#endif
        (entry, var exception) = ImportFromJsonInt(jsonText);
        if (entry != null) {
            return true;
        } else {
            return false;
        }
    }

    /// <summary>
    /// Returns imported entry based on JSON object text.
    /// </summary>
    public static (Entry? entry, string? exceptionText) ImportFromJsonInt(string jsonText) {
        if (string.IsNullOrWhiteSpace(jsonText)) { return (null, "No data."); }

        try {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(jsonText));
            if (!reader.Read() || (reader.TokenType != JsonTokenType.StartObject)) { return (null, "Cannot find JSON start object."); }

            var records = new List<Record>();

            while (reader.Read()) {
                if (reader.TokenType == JsonTokenType.PropertyName) {
                    var propName = reader.GetString();
                    if (propName == null) {
                        return (null, "Unexpected null property name.");
                    } else if (propName.Equals("kind", StringComparison.Ordinal)) {
                        reader.Read();
                        if (reader.TokenType == JsonTokenType.String) {
                            var content = reader.GetString() ?? throw new InvalidDataException("Unexpected null kind.");
                            if (!content.Equals("PWSafe3.Entry", StringComparison.Ordinal)) { throw new InvalidDataException("Unknown kind."); }
                        } else {
                            return (null, "Cannot determine kind.");
                        }
                    } else if (propName.Equals("records", StringComparison.Ordinal)) {
                        if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray) { continue; }

                        while (reader.Read()) {
                            if (reader.TokenType == JsonTokenType.EndArray) { break; }
                            if (reader.TokenType != JsonTokenType.StartObject) { continue; }

                            RecordType? recordType = null;
                            string? caption = null;
                            string? text = null;
                            Guid? uuid = null;
                            DateTime? time = null;
                            int? version = null;
                            byte[]? binary = null;
                            bool? isSensitive = null;

                            while (reader.Read()) {
                                if (reader.TokenType == JsonTokenType.EndObject) { break; }
                                if (reader.TokenType != JsonTokenType.PropertyName) { continue; }

                                var name = reader.GetString();
                                if (!reader.Read()) { break; }

                                switch (name) {
                                    case "type":
                                        if (reader.TokenType == JsonTokenType.String) {
                                            var content = reader.GetString();
                                            if (Enum.TryParse<RecordType>(content, out var parsed)) {
                                                recordType = parsed;
                                            } else {
                                                return (null, $"Cannot convert '{content}' to record type.");
                                            }
                                        } else {
                                            return (null, "Unexpected record type.");
                                        }
                                        break;

                                    case "caption":
                                        if (reader.TokenType == JsonTokenType.String) {
                                            caption = reader.GetString();
                                        } else {
                                            return (null, "Unexpected caption type.");
                                        }
                                        break;

                                    case "text":
                                        if (reader.TokenType == JsonTokenType.String) {
                                            text = reader.GetString();
                                        } else {
                                            return (null, "Unexpected text type.");
                                        }
                                        break;

                                    case "uuid":
                                        if (reader.TokenType == JsonTokenType.String) {
                                            var content = reader.GetString();
                                            if (Guid.TryParse(content, out var parsed)) {
                                                uuid = parsed;
                                            } else {
                                                return (null, $"Cannot convert '{content}' to UUID.");
                                            }
                                        } else {
                                            return (null, "Unexpected UUID type.");
                                        }
                                        break;

                                    case "time":
                                        if (reader.TokenType == JsonTokenType.String) {
                                            var content = reader.GetString();
                                            if (DateTime.TryParse(content, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var value)) {
                                                time = value;
                                            } else {
                                                return (null, $"Cannot convert '{content}' to time.");
                                            }
                                        } else {
                                            return (null, "Unexpected time type.");
                                        }
                                        break;

                                    case "version":
                                        if (reader.TokenType == JsonTokenType.String) {
                                            var content = reader.GetString();
                                            if (int.TryParse(content, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)) {
                                                version = value;
                                            } else {
                                                return (null, $"Cannot convert '{content}' to version.");
                                            }
                                        } else {
                                            return (null, "Unexpected version type.");
                                        }
                                        break;

                                    case "binary":
                                        if (reader.TokenType == JsonTokenType.String) {
                                            var content = reader.GetString() ?? "";
#if NET10_0_OR_GREATER
                                            var binaryBuffer = new byte[content.Length];
                                            if (Convert.TryFromBase64String(content, binaryBuffer, out var bytesInBuffer)) {
                                                binary = new byte[bytesInBuffer];
                                                Buffer.BlockCopy(binaryBuffer, 0, binary, 0, binary.Length);
                                            } else {
                                                return (null, $"Cannot convert '{content}' to binary.");
                                            }
#else
                                        try {
                                            binary = Convert.FromBase64String(content);
                                        } catch (FormatException) {
                                            return (null, $"Cannot convert '{content}' to binary.");
                                        }
#endif
                                        } else {
                                            return (null, "Unexpected binary type.");
                                        }
                                        break;

                                    case "isSensitive":
                                        if (reader.TokenType == JsonTokenType.True) {
                                            isSensitive = true;
                                        } else if (reader.TokenType == JsonTokenType.False) {
                                            isSensitive = false;
                                        } else {
                                            return (null, "Unexpected isSensitive type.");
                                        }
                                        break;


                                    default: return (null, $"Unexpected '{name}' property.");
                                }
                            }

                            if (recordType != null) {
                                switch (Record.GetDataType(recordType.Value)) {
                                    case PasswordSafeFieldDataType.Version:
                                        if (version == null) { return (null, "Version is missing."); }
                                        records.Add(new Record(recordType.Value) {
                                            Version = version.Value
                                        });
                                        break;
                                    case PasswordSafeFieldDataType.Uuid:
                                        if (uuid == null) { return (null, "UUID is missing."); }
                                        records.Add(new Record(recordType.Value) {
                                            Uuid = uuid.Value
                                        });
                                        break;
                                    case PasswordSafeFieldDataType.Time:
                                        if (time == null) { return (null, "Time is missing."); }
                                        records.Add(new Record(recordType.Value) {
                                            Time = time.Value
                                        });
                                        break;
                                    case PasswordSafeFieldDataType.Text:
                                        records.Add(new Record(recordType.Value) {
                                            Text = text
                                        });
                                        break;
                                    case PasswordSafeFieldDataType.Binary:
                                        if (binary == null) { return (null, "Binary data is missing."); }
                                        var record = new Record(recordType.Value);
                                        record.SetBytes(binary);
                                        break;
                                    case PasswordSafeFieldDataType.Unknown:
                                    default:
                                        if (recordType == RecordType.CustomTextField) {
                                            records.Add(new CustomTextRecord() {
                                                Caption = caption,
                                                Text = text,
                                                IsSensitive = isSensitive ?? false
                                            });
                                        } else {
                                            var recordA = new Record(recordType.Value);
                                            if (text != null) {
                                                recordA.Text = text;
                                            } else if (time != null) {
                                                recordA.Time = time.Value;
                                            } else if (uuid != null) {
                                                recordA.Uuid = uuid.Value;
                                            } else if (version != null) {
                                                recordA.Version = version.Value;
                                            } else if (binary != null) {
                                                recordA.SetBytes(binary);
                                            } else {
                                                return (null, "Record data cannot be determined.");
                                            }
                                        }
                                        break;
                                }
                            } else {
                                return (null, "Record type is missing.");
                            }
                        }
                    } else {
                        return (null, $"Unexpected '{propName}' property.");
                    }
                } else if (reader.TokenType == JsonTokenType.EndObject) {
                    break;
                }
            }

            return (new Entry(records), null);
        } catch (JsonException ex) {
            return (null, ex.Message);
        }
    }

    #endregion Export/Import

}
