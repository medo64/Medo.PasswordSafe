using System;
using Xunit;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    public class RecordCollectionTests {

        [Fact]
        public void RecordCollection_New() {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry());
            doc.Entries[0].Records.Add(new PwSafe.Record(PwSafe.RecordType.Group) { Text = "Test" });

            Assert.True(string.Equals("Test", doc.Entries[0].Group, StringComparison.Ordinal));
        }


        [Fact]
        public void RecordCollection_ReadOnly() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.Entries.Add(new PwSafe.Entry());
                doc.IsReadOnly = true;
                doc.Entries[0].Records.Add(new PwSafe.Record(PwSafe.RecordType.Group));
            });
        }

        [Fact]
        public void RecordCollection_ReadOnly_IndexerRead() {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry());
            doc.IsReadOnly = true;
            Assert.Equal("", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
        }

        [Fact]
        public void RecordCollection_ReadOnly_IndexerWrite() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.Entries.Add(new PwSafe.Entry());
                doc.IsReadOnly = true;
                doc.Entries[0].Records[PwSafe.RecordType.Title] = null;
            });
        }

    }
}
