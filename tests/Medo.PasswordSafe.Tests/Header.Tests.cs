using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class Header_Tests {

    [TestMethod]  // Header: New
    public void Header_New() {
        var field = new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Text = "Test" };
        Assert.AreEqual("Test", field.Text);
    }

    [TestMethod]  // Header: New (wrong type)
    public void Header_New_WrongType() {
        Assert.ThrowsException<FormatException>(() => {
            var field = new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Uuid = new Guid() };
        });
    }


    [TestMethod]  // Header: Add (read-only document)
    public void Header_ReadOnly() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password");
            doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Text = "Test" });

            doc.IsReadOnly = true;
            doc.Headers[PwSafe.HeaderType.DatabaseName].Text = "NewName";
        });
    }

    [TestMethod]  // Header: Indexer Get
    public void Header_ReadOnly_IndexerRead() {
        var doc = new PwSafe.Document("Password") { IsReadOnly = true };
        Assert.IsNotNull(doc.Headers[PwSafe.HeaderType.DatabaseName]);
        Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.DatabaseName].Text);
    }

    [TestMethod]  // Header: Indexer Set
    public void Header_ReadOnly_IndexerWrite() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password") { IsReadOnly = true };
            doc.Headers.Remove(PwSafe.HeaderType.DatabaseName);
        });
    }

}
