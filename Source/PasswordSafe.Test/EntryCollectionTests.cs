using System;
using Xunit;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    public class EntryCollectionTests {

        [Fact]
        public void EntryCollection_New() {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry("Test"));

            Assert.Equal("Test", doc.Entries[0].Title);
        }


        [Fact]
        public void EntryCollection_ReadOnly() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.IsReadOnly = true;
                doc.Entries.Add(new PwSafe.Entry());
            });
        }

        [Fact]
        public void EntryCollection_ReadOnly_IndexerRead() {
            var doc = new PwSafe.Document("Password");
            doc.IsReadOnly = true;
            Assert.NotNull(doc.Entries["Test"]);
            Assert.Equal("", doc.Entries["Test"].Title);
            Assert.NotNull(doc.Entries["Test", PwSafe.RecordType.Title]);
            Assert.Equal("", doc.Entries["Test", PwSafe.RecordType.Title].Text);
        }

        [Fact]
        public void EntryCollection_ReadOnly_IndexerWrite() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.IsReadOnly = true;
                doc.Entries["A"] = new PwSafe.Entry();
            });
        }

        [Fact]
        public void EntryCollection_ReadOnly_IndexerWrite2() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.Entries.Add(new PwSafe.Entry("A"));
                doc.IsReadOnly = true;
                doc.Entries["A"][PwSafe.RecordType.EmailAddress] = null;
            });
        }

        [Fact]
        public void EntryCollection_ReadOnly_IndexerWrite3() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.Entries.Add(new PwSafe.Entry("A"));
                doc.IsReadOnly = true;
                doc.Entries["A", PwSafe.RecordType.EmailAddress] = null;
            });
        }

        [Fact]
        public void EntryCollection_ReadOnly_IndexerWrite4() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.Entries.Add(new PwSafe.Entry("X.Y", "A"));
                doc.IsReadOnly = true;
                doc.Entries["X.Y", "A", PwSafe.RecordType.EmailAddress] = null;
            });
        }


        [Fact]
        public void EntryCollection_IndexerReadByTitleNonEmpty() {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry("A"));
            Assert.Equal("A", doc.Entries["A"].Title);

            doc.Entries["A"].Title = "B";
            Assert.Equal("B", doc.Entries["B"].Title);
        }

        [Fact]
        public void EntryCollection_IndexerReadByTitleTypeNonEmpty() {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry("A"));
            Assert.Equal("A", doc.Entries["A"][PwSafe.RecordType.Title].Text);

            doc.Entries["A"].Title = "B";
            Assert.Equal("B", doc.Entries["B"][PwSafe.RecordType.Title].Text);
        }

        [Fact]
        public void EntryCollection_IndexerReadByGroupTitleTypeNonEmpty() {
            var doc = new PwSafe.Document("Password");
            doc.Entries.Add(new PwSafe.Entry("X.Y", "A"));
            Assert.Equal("X.Y", doc.Entries["A"][PwSafe.RecordType.Group].Text);
            Assert.Equal("A", doc.Entries["A"][PwSafe.RecordType.Title].Text);

            doc.Entries["A"].Group = doc.Entries["A"].Group.Up();
            doc.Entries["A"].Title = "B";
            Assert.Equal("X", doc.Entries["B"][PwSafe.RecordType.Group].Text);
            Assert.Equal("B", doc.Entries["B"][PwSafe.RecordType.Title].Text);
        }


        [Fact]
        public void EntryCollection_IndexerReadByTitle() {
            var doc = new PwSafe.Document("Password");
            Assert.NotEqual(Guid.Empty, doc.Entries["A"].Uuid);
            Assert.Equal("A", doc.Entries["A"].Title);
        }

        [Fact]
        public void EntryCollection_IndexerReadByTitleType() {
            var doc = new PwSafe.Document("Password");
            Assert.NotEqual(Guid.Empty, doc.Entries["A", PwSafe.RecordType.Uuid].Uuid);
            Assert.Equal("A", doc.Entries["A", PwSafe.RecordType.Title].Text);
            Assert.NotEqual(Guid.Empty, doc.Entries["A"][PwSafe.RecordType.Uuid].Uuid);
            Assert.Equal("A", doc.Entries["A"][PwSafe.RecordType.Title].Text);
        }

        [Fact]
        public void EntryCollection_IndexerReadByGroupTitleType() {
            var doc = new PwSafe.Document("Password");
            Assert.NotEqual(Guid.Empty, doc.Entries["X.Y", "A", PwSafe.RecordType.Uuid].Uuid);
            Assert.Equal("X.Y", doc.Entries["X.Y", "A", PwSafe.RecordType.Group].Text);
            Assert.Equal("A", doc.Entries["X.Y", "A", PwSafe.RecordType.Title].Text);
            Assert.NotEqual(Guid.Empty, doc.Entries["X.Y", "A"][PwSafe.RecordType.Uuid].Uuid);
            Assert.Equal("A", doc.Entries["X.Y", "A"][PwSafe.RecordType.Title].Text);
        }

    }
}
