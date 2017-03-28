using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    [TestClass]
    public class HeaderCollectionTests {

        [TestMethod]
        public void HeaderCollection_New() {
            var doc = new Document("Password");
            doc.Headers.Add(new Header(HeaderType.DatabaseName) { Text = "Test" });

            Assert.AreEqual("Test", doc.Name);
        }


        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void HeaderCollection_ReadOnly() {
            var doc = new Document("Password");
            doc.IsReadOnly = true;
            doc.Headers.Add(new Header(HeaderType.DatabaseName) { Text = "Test" });
        }

        [TestMethod]
        public void HeaderCollection_ReadOnly_IndexerRead() {
            var doc = new Document("Password");
            doc.IsReadOnly = true;
            Assert.IsNotNull(doc.Headers[HeaderType.DatabaseName]);
            Assert.AreEqual("", doc.Headers[HeaderType.DatabaseName].Text);
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void HeaderCollection_ReadOnly_IndexerWrite() {
            var doc = new Document("Password");
            doc.IsReadOnly = true;
            doc.Headers[HeaderType.DatabaseName] = null;
        }

    }
}
