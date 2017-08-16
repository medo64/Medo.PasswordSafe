using System;
using Xunit;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    public class HeaderCollectionTests {

        [Fact]
        public void HeaderCollection_New() {
            var doc = new PwSafe.Document("Password");
            doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Text = "Test" });

            Assert.Equal("Test", doc.Name);
        }


        [Fact]
        public void HeaderCollection_ReadOnly() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.IsReadOnly = true;
                doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Text = "Test" });
            });
        }

        [Fact]
        public void HeaderCollection_ReadOnly_IndexerRead() {
            var doc = new PwSafe.Document("Password");
            doc.IsReadOnly = true;
            Assert.NotNull(doc.Headers[PwSafe.HeaderType.DatabaseName]);
            Assert.Equal("", doc.Headers[PwSafe.HeaderType.DatabaseName].Text);
        }

        [Fact]
        public void HeaderCollection_ReadOnly_IndexerWrite() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.IsReadOnly = true;
                doc.Headers[PwSafe.HeaderType.DatabaseName] = null;
            });
        }

    }
}
