using System;
using Xunit;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {
    public class RecordTests {

        [Fact]
        public void Record_New() {
            var field = new PwSafe.Record(PwSafe.RecordType.Title) { Text = "Test" };
            Assert.Equal("Test", field.Text);
        }

        [Fact]
        public void Record_New_WrongType() {
            Assert.Throws<FormatException>(() => {
                var field = new PwSafe.Record(PwSafe.RecordType.Title) { Time = DateTime.Now };
            });
        }

        [Fact]
        public void Record_New_Autotype() {
            var field = new PwSafe.Record(PwSafe.RecordType.Autotype);
            Assert.Equal(@"\u\t\p\n", field.Text);
        }


        [Fact]
        public void Record_ReadOnly() {
            Assert.Throws<NotSupportedException>(() => {
                var doc = new PwSafe.Document("Password");
                doc.Entries["Test"].Password = "Old";

                doc.IsReadOnly = true;
                doc.Entries[0].Records[PwSafe.RecordType.Password].Text = "New";
            });
        }

    }
}
