namespace Medo.Security.Cryptography.PasswordSafe;

using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Serialization;
using System.Text;

/// <summary>
/// Custom text field (0x30).
/// </summary>
[DebuggerDisplay("{RecordType}: {ToString(),nq}")]
public sealed class CustomTextRecord : Record {

    /// <summary>
    /// Create a new instance.
    /// </summary>
    public CustomTextRecord()
        : base(RecordType.CustomTextField) {
    }

    internal CustomTextRecord(byte[] rawData)
        : base(RecordType.CustomTextField, rawData) {
    }

    internal CustomTextRecord(RecordCollection owner)
        : this() {
        Owner = owner;
    }


    /// <summary>
    /// Gets/sets caption.
    /// Caption is not localized.
    /// </summary>
    public override string? Caption {
        get {
            ParseData(RawData, out var caption, out var _, out var _);
            return caption;
        }
        set {

        }
    }

    /// <summary>
    /// Gets/sets text data.
    /// Null will be returned if conversion cannot be performed.
    /// For unknown field types, conversion will always be attempted.
    /// </summary>
    public override string? Text {
        get {
            ParseData(RawData, out var _, out var text, out var _);
            return text;
        }
        set {
        }
    }

    /// <summary>
    /// Gets/sets if object is sensitive.
    /// Sensitive fields should be shown to user hidden by default.
    /// </summary>
    public override bool IsSensitive {
        get {
            ParseData(RawData, out var _, out var _, out var isSensitive);
            return isSensitive;
        }
        set {

        }
    }


    /// <summary>
    /// Returns the exact copy of the record.
    /// </summary>
    public override Record Clone() {
        return new CustomTextRecord(base.GetRawDataDirect());
    }


    private static bool ParseData(byte[] rawData, out string caption, out string text, out bool isSensitive) {
        caption = "";
        text = "";
        isSensitive = false;
        if (rawData == null) { return false; }

        var rawText = UTF8Encoding.UTF8.GetString(rawData);
        var index = 0;
        while (index < rawData.Length) {
            if (index + 2 > rawData.Length) { return false; }
#if NETSTANDARD2_0
            if (!int.TryParse(rawText.Substring(index, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var propId)) { return false; }
#else
            if (!int.TryParse(rawText.AsSpan(index, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var propId)) { return false; }
#endif
            index += 2;

            if (index + 4 > rawData.Length) { return false; }
#if NETSTANDARD2_0
            if (!int.TryParse(rawText.Substring(index, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var propLength)) { return false; }
#else
            if (!int.TryParse(rawText.AsSpan(index, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var propLength)) { return false; }
#endif
            index += 4;

            if (index + propLength > rawData.Length) { return false; }
            var propText = rawText.Substring(index, propLength);
            index += propLength;

            switch (propId) {
                case 0x00: return true;  // code currently doesn't support parsing of multiple entries, only the first one is taken
                case 0x01: caption = propText; break;
                case 0x02: text = propText; break;
                case 0x03: isSensitive = propText.Equals("1", StringComparison.Ordinal); break;
                default: break;
            }
        }
        return true;
    }

}
