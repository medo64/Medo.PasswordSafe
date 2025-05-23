using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class RecordCollection_Tests {

    [TestMethod]  // RecordCollection: Add
    public void RecordCollection_New() {
        var doc = new PwSafe.Document("Password");
        doc.Entries.Add(new PwSafe.Entry());
        doc.Entries[0].Records.Add(new PwSafe.Record(PwSafe.RecordType.Group) { Text = "Test" });
        Assert.IsTrue(string.Equals("Test", doc.Entries[0].Group, StringComparison.Ordinal));
    }


    [TestMethod]  // RecordCollection: Add (read-only document)
    public void RecordCollection_ReadOnly() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry());
            doc.IsReadOnly = true;
            doc.Entries[0].Records.Add(new PwSafe.Record(PwSafe.RecordType.Group));
        });
    }

    [TestMethod]  // RecordCollection: Indexer Get
    public void RecordCollection_ReadOnly_IndexerRead() {
        var doc = new PwSafe.Document("Password");
        doc.Entries.Add(new PwSafe.Entry());
        doc.IsReadOnly = true;
        Assert.AreEqual("", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
    }

    [TestMethod]  // RecordCollection: Indexer Set
    public void RecordCollection_ReadOnly_IndexerWrite() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry());
            doc.IsReadOnly = true;
            doc.Entries[0].Records.Remove(PwSafe.RecordType.Title);
        });
    }

}
