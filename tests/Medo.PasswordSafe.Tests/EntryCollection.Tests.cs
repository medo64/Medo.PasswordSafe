using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class EntryCollection_Tests {

    [TestMethod]  // EntryCollection: Add")]
    public void EntryCollection_New() {
        var doc = new PwSafe.Document("Password");
        doc.Entries.Add(new PwSafe.Entry("Test"));
        Assert.AreEqual("Test", doc.Entries[0].Title);
    }


    [TestMethod]  // EntryCollection: Add (read-only document")]
    public void EntryCollection_ReadOnly() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password") { IsReadOnly = true };
            doc.Entries.Add(new PwSafe.Entry());
        });
    }

    [TestMethod]  // EntryCollection: Indexer Get (read-only document)")]
    public void EntryCollection_ReadOnly_IndexerRead() {
        var doc = new PwSafe.Document("Password") { IsReadOnly = true };
        Assert.IsNotNull(doc.Entries["Test"]);
        Assert.AreEqual("", doc.Entries["Test"].Title);
        Assert.IsNotNull(doc.Entries["Test", PwSafe.RecordType.Title]);
        Assert.AreEqual("", doc.Entries["Test", PwSafe.RecordType.Title].Text);
    }

    [TestMethod]  // EntryCollection: Indexer Set 2 (read-only document)")]
    public void EntryCollection_ReadOnly_IndexerWrite2() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry("A"));
            doc.IsReadOnly = true;
            doc.Entries.Remove("A", PwSafe.RecordType.EmailAddress);
        });
    }

    [TestMethod]  // EntryCollection: Indexer Set 3 (read-only document)")]
    public void EntryCollection_ReadOnly_IndexerWrite3() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry("A"));
            doc.IsReadOnly = true;
            doc.Entries.Remove("A", PwSafe.RecordType.EmailAddress);
        });
    }

    [TestMethod]  // EntryCollection: Indexer Set 4 (read-only document)")]
    public void EntryCollection_ReadOnly_IndexerWrite4() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry("X.Y", "A"));
            doc.IsReadOnly = true;
            doc.Entries.Remove("X.Y", "A", PwSafe.RecordType.EmailAddress);
        });
    }


    [TestMethod]  // EntryCollection: Indexer Get via Title")]
    public void EntryCollection_IndexerReadByTitleNonEmpty() {
        var doc = new PwSafe.Document("Password");
        doc.Entries.Add(new PwSafe.Entry("A"));
        Assert.AreEqual("A", doc.Entries["A"].Title);

        doc.Entries["A"].Title = "B";
        Assert.AreEqual("B", doc.Entries["B"].Title);
    }

    [TestMethod]  // EntryCollection: Indexer Get via Title (type non-empty)")]
    public void EntryCollection_IndexerReadByTitleTypeNonEmpty() {
        var doc = new PwSafe.Document("Password");
        doc.Entries.Add(new PwSafe.Entry("A"));
        Assert.AreEqual("A", doc.Entries["A"][PwSafe.RecordType.Title].Text);

        doc.Entries["A"].Title = "B";
        Assert.AreEqual("B", doc.Entries["B"][PwSafe.RecordType.Title].Text);
    }

    [TestMethod]  // EntryCollection: Indexer Get via Group and Title (type non-empty)")]
    public void EntryCollection_IndexerReadByGroupTitleTypeNonEmpty() {
        var doc = new PwSafe.Document("Password");
        doc.Entries.Add(new PwSafe.Entry("X.Y", "A"));
        Assert.AreEqual("X.Y", doc.Entries["A"][PwSafe.RecordType.Group].Text);
        Assert.AreEqual("A", doc.Entries["A"][PwSafe.RecordType.Title].Text);

        doc.Entries["A"].Group = doc.Entries["A"].Group.Up();
        doc.Entries["A"].Title = "B";
        Assert.AreEqual("X", doc.Entries["B"][PwSafe.RecordType.Group].Text);
        Assert.AreEqual("B", doc.Entries["B"][PwSafe.RecordType.Title].Text);
    }


    [TestMethod]  // EntryCollection: Indexer Get via Title")]
    public void EntryCollection_IndexerReadByTitle() {
        var doc = new PwSafe.Document("Password");
        Assert.AreNotEqual(Guid.Empty, doc.Entries["A"].Uuid);
        Assert.AreEqual("A", doc.Entries["A"].Title);
    }

    [TestMethod]  // EntryCollection: Indexer Get via Title and Type")]
    public void EntryCollection_IndexerReadByTitleType() {
        var doc = new PwSafe.Document("Password");
        Assert.AreNotEqual(Guid.Empty, doc.Entries["A", PwSafe.RecordType.Uuid].Uuid);
        Assert.AreEqual("A", doc.Entries["A", PwSafe.RecordType.Title].Text);
        Assert.AreNotEqual(Guid.Empty, doc.Entries["A"][PwSafe.RecordType.Uuid].Uuid);
        Assert.AreEqual("A", doc.Entries["A"][PwSafe.RecordType.Title].Text);
    }

    [TestMethod]  // EntryCollection: Indexer Get via Group, Title, and Type")]
    public void EntryCollection_IndexerReadByGroupTitleType() {
        var doc = new PwSafe.Document("Password");
        Assert.AreNotEqual(Guid.Empty, doc.Entries["X.Y", "A", PwSafe.RecordType.Uuid].Uuid);
        Assert.AreEqual("X.Y", doc.Entries["X.Y", "A", PwSafe.RecordType.Group].Text);
        Assert.AreEqual("A", doc.Entries["X.Y", "A", PwSafe.RecordType.Title].Text);
        Assert.AreNotEqual(Guid.Empty, doc.Entries["X.Y", "A"][PwSafe.RecordType.Uuid].Uuid);
        Assert.AreEqual("A", doc.Entries["X.Y", "A"][PwSafe.RecordType.Title].Text);
    }

}
