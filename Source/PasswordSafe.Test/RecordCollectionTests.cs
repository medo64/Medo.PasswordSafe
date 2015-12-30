using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    [TestClass]
    public class RecordCollectionTests {

        [TestMethod]
        public void RecordCollection_New() {
            var doc = new Document();
            doc.Entries.Add(new Entry());
            doc.Entries[0].Records.Add(new Record(RecordType.Group) { Text = "Test" });

            Assert.AreEqual("Test", doc.Entries[0].Group);
        }


        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void RecordCollection_ReadOnly() {
            var doc = new Document();
            doc.Entries.Add(new Entry());
            doc.IsReadOnly = true;
            doc.Entries[0].Records.Add(new Record(RecordType.Group));
        }

        [TestMethod]
        public void RecordCollection_ReadOnly_IndexerRead() {
            var doc = new Document();
            doc.Entries.Add(new Entry());
            doc.IsReadOnly = true;
            Assert.AreEqual("", doc.Entries[0].Records[RecordType.Title].Text);
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void RecordCollection_ReadOnly_IndexerWrite() {
            var doc = new Document();
            doc.Entries.Add(new Entry());
            doc.IsReadOnly = true;
            doc.Entries[0].Records[RecordType.Title] = null;
        }

    }
}
