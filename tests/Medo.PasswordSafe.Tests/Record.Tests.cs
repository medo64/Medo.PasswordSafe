using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class Record_Tests {

    [TestMethod]  // Record: New
    public void Record_New() {
        var field = new PwSafe.Record(PwSafe.RecordType.Title) { Text = "Test" };
        Assert.AreEqual("Test", field.Text);
    }

    [TestMethod]  // Record: New (wrong type
    public void Record_New_WrongType() {
        Assert.ThrowsException<FormatException>(() => {
            var field = new PwSafe.Record(PwSafe.RecordType.Title) { Time = DateTime.Now };
        });
    }

    [TestMethod]  // Record: New (auto-type)
    public void Record_New_Autotype() {
        var field = new PwSafe.Record(PwSafe.RecordType.Autotype);
        Assert.AreEqual(@"\u\t\p\n", field.Text);
    }


    [TestMethod]  // Record: Change (read-only document)
    public void Record_ReadOnly() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password");
            doc.Entries["Test"].Password = "Old";

            doc.IsReadOnly = true;
            doc.Entries[0].Records[PwSafe.RecordType.Password].Text = "New";
        });
    }


    [TestMethod]  // Record: SetBytes
    public void Record_SetBytes() {
        var field = new PwSafe.Record(PwSafe.RecordType.Title);
        field.SetBytes(new byte[] { 0x00, 0xFF });
        Assert.AreEqual("00-FF", BitConverter.ToString(field.GetBytes()));
    }

    [TestMethod]  // Record: SetBytes (null)
    public void Record_SetBytes_Null() {
        Assert.ThrowsException<ArgumentNullException>(() => {
            var field = new PwSafe.Record(PwSafe.RecordType.Title);
            field.SetBytes(null);
        });
    }

}
