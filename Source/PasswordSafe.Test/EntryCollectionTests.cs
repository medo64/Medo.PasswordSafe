using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    [TestClass]
    public class EntryCollectionTests {

        [TestMethod]
        public void EntryCollection_New() {
            var doc = new Document();
            doc.Entries.Add(new Entry("Test"));

            Assert.AreEqual("Test", doc.Entries[0].Title);
        }


        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void EntryCollection_ReadOnly() {
            var doc = new Document();
            doc.IsReadOnly = true;
            doc.Entries.Add(new Entry());
        }

        [TestMethod]
        public void EntryCollection_ReadOnly_IndexerRead() {
            var doc = new Document();
            doc.IsReadOnly = true;
            Assert.IsNotNull(doc.Entries["Test"]);
            Assert.AreEqual("", doc.Entries["Test"].Title);
            Assert.IsNotNull(doc.Entries["Test", RecordType.Title]);
            Assert.AreEqual("", doc.Entries["Test", RecordType.Title].Text);
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void EntryCollection_ReadOnly_IndexerWrite() {
            var doc = new Document();
            doc.IsReadOnly = true;
            doc.Entries["A"] = new Entry();
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void EntryCollection_ReadOnly_IndexerWrite2() {
            var doc = new Document();
            doc.Entries.Add(new Entry("A"));
            doc.IsReadOnly = true;
            doc.Entries["A"][RecordType.EmailAddress] = null;
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void EntryCollection_ReadOnly_IndexerWrite3() {
            var doc = new Document();
            doc.Entries.Add(new Entry("A"));
            doc.IsReadOnly = true;
            doc.Entries["A", RecordType.EmailAddress] = null;
        }


        [TestMethod]
        public void EntryCollection_IndexerReadByNameNonEmpty() {
            var doc = new Document();
            doc.Entries.Add(new Entry("A"));
            Assert.AreEqual("A", doc.Entries["A"].Title);

            doc.Entries["A"].Title = "B";
            Assert.AreEqual("B", doc.Entries["B"].Title);
        }

        [TestMethod]
        public void EntryCollection_IndexerReadByNameAndTypeNonEmpty() {
            var doc = new Document();
            doc.Entries.Add(new Entry("A"));
            Assert.AreEqual("A", doc.Entries["A"][RecordType.Title].Text);

            doc.Entries["A"].Title = "B";
            Assert.AreEqual("B", doc.Entries["B"][RecordType.Title].Text);
        }


        [TestMethod]
        public void EntryCollection_IndexerReadByName() {
            var doc = new Document();
            Assert.AreNotEqual(Guid.Empty, doc.Entries["A"].Uuid);
            Assert.AreEqual("A", doc.Entries["A"].Title);
        }

        [TestMethod]
        public void EntryCollection_IndexerReadByNameAndType() {
            var doc = new Document();
            Assert.AreNotEqual(Guid.Empty, doc.Entries["A", RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries["A", RecordType.Title].Text);
            Assert.AreNotEqual(Guid.Empty, doc.Entries["A"][RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries["A"][RecordType.Title].Text);
        }

    }
}
