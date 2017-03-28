using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    [TestClass]
    public class EntryCollectionTests {

        [TestMethod]
        public void EntryCollection_New() {
            var doc = new Document("Password");
            doc.Entries.Add(new Entry("Test"));

            Assert.AreEqual("Test", doc.Entries[0].Title);
        }


        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void EntryCollection_ReadOnly() {
            var doc = new Document("Password");
            doc.IsReadOnly = true;
            doc.Entries.Add(new Entry());
        }

        [TestMethod]
        public void EntryCollection_ReadOnly_IndexerRead() {
            var doc = new Document("Password");
            doc.IsReadOnly = true;
            Assert.IsNotNull(doc.Entries["Test"]);
            Assert.AreEqual("", doc.Entries["Test"].Title);
            Assert.IsNotNull(doc.Entries["Test", RecordType.Title]);
            Assert.AreEqual("", doc.Entries["Test", RecordType.Title].Text);
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void EntryCollection_ReadOnly_IndexerWrite() {
            var doc = new Document("Password");
            doc.IsReadOnly = true;
            doc.Entries["A"] = new Entry();
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void EntryCollection_ReadOnly_IndexerWrite2() {
            var doc = new Document("Password");
            doc.Entries.Add(new Entry("A"));
            doc.IsReadOnly = true;
            doc.Entries["A"][RecordType.EmailAddress] = null;
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void EntryCollection_ReadOnly_IndexerWrite3() {
            var doc = new Document("Password");
            doc.Entries.Add(new Entry("A"));
            doc.IsReadOnly = true;
            doc.Entries["A", RecordType.EmailAddress] = null;
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void EntryCollection_ReadOnly_IndexerWrite4() {
            var doc = new Document("Password");
            doc.Entries.Add(new Entry("X.Y", "A"));
            doc.IsReadOnly = true;
            doc.Entries["X.Y", "A", RecordType.EmailAddress] = null;
        }


        [TestMethod]
        public void EntryCollection_IndexerReadByTitleNonEmpty() {
            var doc = new Document("Password");
            doc.Entries.Add(new Entry("A"));
            Assert.AreEqual("A", doc.Entries["A"].Title);

            doc.Entries["A"].Title = "B";
            Assert.AreEqual("B", doc.Entries["B"].Title);
        }

        [TestMethod]
        public void EntryCollection_IndexerReadByTitleTypeNonEmpty() {
            var doc = new Document("Password");
            doc.Entries.Add(new Entry("A"));
            Assert.AreEqual("A", doc.Entries["A"][RecordType.Title].Text);

            doc.Entries["A"].Title = "B";
            Assert.AreEqual("B", doc.Entries["B"][RecordType.Title].Text);
        }

        [TestMethod]
        public void EntryCollection_IndexerReadByGroupTitleTypeNonEmpty() {
            var doc = new Document("Password");
            doc.Entries.Add(new Entry("X.Y", "A"));
            Assert.AreEqual("X.Y", doc.Entries["A"][RecordType.Group].Text);
            Assert.AreEqual("A", doc.Entries["A"][RecordType.Title].Text);

            doc.Entries["A"].Group = doc.Entries["A"].Group.Up();
            doc.Entries["A"].Title = "B";
            Assert.AreEqual("X", doc.Entries["B"][RecordType.Group].Text);
            Assert.AreEqual("B", doc.Entries["B"][RecordType.Title].Text);
        }


        [TestMethod]
        public void EntryCollection_IndexerReadByTitle() {
            var doc = new Document("Password");
            Assert.AreNotEqual(Guid.Empty, doc.Entries["A"].Uuid);
            Assert.AreEqual("A", doc.Entries["A"].Title);
        }

        [TestMethod]
        public void EntryCollection_IndexerReadByTitleType() {
            var doc = new Document("Password");
            Assert.AreNotEqual(Guid.Empty, doc.Entries["A", RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries["A", RecordType.Title].Text);
            Assert.AreNotEqual(Guid.Empty, doc.Entries["A"][RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries["A"][RecordType.Title].Text);
        }

        [TestMethod]
        public void EntryCollection_IndexerReadByGroupTitleType() {
            var doc = new Document("Password");
            Assert.AreNotEqual(Guid.Empty, doc.Entries["X.Y", "A", RecordType.Uuid].Uuid);
            Assert.AreEqual("X.Y", doc.Entries["X.Y", "A", RecordType.Group].Text);
            Assert.AreEqual("A", doc.Entries["X.Y", "A", RecordType.Title].Text);
            Assert.AreNotEqual(Guid.Empty, doc.Entries["X.Y", "A"][RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries["X.Y", "A"][RecordType.Title].Text);
        }

    }
}
