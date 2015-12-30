using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    [TestClass]
    public class EntryTests {

        [TestMethod]
        public void Entry_New() {
            var entry = new Entry();
            Assert.AreEqual(3, entry.Records.Count);
            Assert.IsTrue(entry.Records.Contains(RecordType.Uuid));
            Assert.IsTrue(entry.Records.Contains(RecordType.Title));
            Assert.IsTrue(entry.Records.Contains(RecordType.Password));
            Assert.IsTrue(entry.Uuid != Guid.Empty);
            Assert.AreEqual("", entry.Title);
            Assert.AreEqual("", entry.Password);
        }

        [TestMethod]
        public void Entry_New_WithTitle() {
            var entry = new Entry("Test");
            Assert.AreEqual(3, entry.Records.Count);
            Assert.IsTrue(entry.Records.Contains(RecordType.Uuid));
            Assert.IsTrue(entry.Records.Contains(RecordType.Title));
            Assert.IsTrue(entry.Records.Contains(RecordType.Password));
            Assert.IsTrue(entry.Uuid != Guid.Empty);
            Assert.AreEqual("Test", entry.Title);
            Assert.AreEqual("", entry.Password);
        }


        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void Entry_ReadOnly() {
            var doc = new Document();
            doc.Entries["Test"].Password = "Old";

            doc.IsReadOnly = true;
            doc.Entries["Test"].Password = "New";
        }


        [TestMethod]
        public void Entry_AccessByRecordType() {
            var doc = new Document();

            doc.Entries["Test"].Password = "Old";
            Assert.IsTrue(doc.Entries["Test"][RecordType.Uuid].Uuid != Guid.Empty);
            Assert.AreEqual("Old", doc.Entries["Test"][RecordType.Password].Text);

            doc.Entries["Test"][RecordType.Password].Text = "New";
            Assert.AreEqual("New", doc.Entries["Test"][RecordType.Password].Text);
        }

    }
}
