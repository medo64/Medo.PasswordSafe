using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class HeaderCollection_Tests {

    [TestMethod]  // HeaderCollection: Add
    public void HeaderCollection_New() {
        var doc = new PwSafe.Document("Password");
        doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Text = "Test" });
        Assert.AreEqual("Test", doc.Name);
    }


    [TestMethod]  // HeaderCollection: Add (read-only document)
    public void HeaderCollection_ReadOnly() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password") { IsReadOnly = true };
            doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Text = "Test" });
        });
    }

    [TestMethod]  // HeaderCollection: Indexer Get
    public void HeaderCollection_ReadOnly_IndexerRead() {
        var doc = new PwSafe.Document("Password") { IsReadOnly = true };
        Assert.IsNotNull(doc.Headers[PwSafe.HeaderType.DatabaseName]);
        Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.DatabaseName].Text);
    }

    [TestMethod]  // HeaderCollection: Indexer Set
    public void HeaderCollection_ReadOnly_IndexerWrite() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password") { IsReadOnly = true };
            doc.Headers.Remove(PwSafe.HeaderType.DatabaseName);
        });
    }

}
