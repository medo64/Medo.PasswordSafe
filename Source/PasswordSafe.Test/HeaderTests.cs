using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    [TestClass]
    public class HeaderTests {

        [TestMethod]
        public void Header_New() {
            var field = new Header(HeaderType.DatabaseName) { Text = "Test" };
            Assert.AreEqual("Test", field.Text);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void Header_New_WrongType() {
            var field = new Header(HeaderType.DatabaseName) { Uuid = new Guid() };
        }


        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void Header_ReadOnly() {
            var doc = new Document();
            doc.Headers.Add(new Header(HeaderType.DatabaseName) { Text = "Test" });

            doc.IsReadOnly = true;
            doc.Headers[HeaderType.DatabaseName].Text = "NewName";
        }

        [TestMethod]
        public void Header_ReadOnly_IndexerRead() {
            var doc = new Document();
            doc.IsReadOnly = true;
            Assert.IsNotNull(doc.Headers[HeaderType.DatabaseName]);
            Assert.AreEqual("", doc.Headers[HeaderType.DatabaseName].Text);
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void Header_ReadOnly_IndexerWrite() {
            var doc = new Document();
            doc.IsReadOnly = true;
            doc.Headers[HeaderType.DatabaseName] = null;
        }

    }
}
