using System;
using Xunit;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    public class HeaderTests {

        [Fact]
        public void Header_New() {
            var field = new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Text = "Test" };
            Assert.Equal("Test", field.Text);
        }

        [Fact]
        public void Header_New_WrongType() {
            Assert.Throws<FormatException>(() => {
                var field = new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Uuid = new Guid() };
            });
        }


        [Fact]
        public void Header_ReadOnly() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.DatabaseName) { Text = "Test" });

                doc.IsReadOnly = true;
                doc.Headers[PwSafe.HeaderType.DatabaseName].Text = "NewName";
            });
        }

        [Fact]
        public void Header_ReadOnly_IndexerRead() {
            var doc = new PwSafe.Document("Password");
            doc.IsReadOnly = true;
            Assert.NotNull(doc.Headers[PwSafe.HeaderType.DatabaseName]);
            Assert.Equal("", doc.Headers[PwSafe.HeaderType.DatabaseName].Text);
        }

        [Fact]
        public void Header_ReadOnly_IndexerWrite() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.IsReadOnly = true;
                doc.Headers[PwSafe.HeaderType.DatabaseName] = null;
            });
        }

    }
}
