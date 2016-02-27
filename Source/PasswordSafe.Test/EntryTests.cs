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
            var doc = new Document("Password");
            doc.Entries["Test"].Password = "Old";

            doc.IsReadOnly = true;
            doc.Entries["Test"].Password = "New";
        }


        [TestMethod]
        public void Entry_AccessByRecordType() {
            var doc = new Document("Password");

            doc.Entries["Test"].Password = "Old";
            Assert.IsTrue(doc.Entries["Test"][RecordType.Uuid].Uuid != Guid.Empty);
            Assert.AreEqual("Old", doc.Entries["Test"][RecordType.Password].Text);

            doc.Entries["Test"][RecordType.Password].Text = "New";
            Assert.AreEqual("New", doc.Entries["Test"][RecordType.Password].Text);
        }


        [TestMethod]
        public void Entry_TestNamed() {
            var guid = Guid.NewGuid();

            var doc = new Document("Password") { TrackAccess = false, TrackModify = false };
            var entry = new Entry();
            doc.Entries.Add(entry);

            entry.Uuid = guid;
            entry.Group = "Group";
            entry.Title = "Title";
            entry.UserName = "UserName";
            entry.Notes = "Notes";
            entry.Password = "Password";
            entry.CreationTime = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            entry.PasswordModificationTime = new DateTime(2002, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            entry.LastAccessTime = new DateTime(2003, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            entry.PasswordExpiryTime = new DateTime(2004, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            entry.LastModificationTime = new DateTime(2005, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            entry.Url = "http://example.com";
            entry.TwoFactorKey = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            entry.CreditCardNumber = "1234 5678 9012 3456";
            entry.CreditCardExpiration = "Title";
            entry.CreditCardVerificationValue = "0987";
            entry.CreditCardPin = "6543";

            Assert.AreEqual(guid, entry.Uuid);
            Assert.AreEqual("Group", (string)entry.Group);
            Assert.AreEqual("Title", entry.Title);
            Assert.AreEqual("UserName", entry.UserName);
            Assert.AreEqual("Notes", entry.Notes);
            Assert.AreEqual("Password", entry.Password);
            Assert.AreEqual(new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry.CreationTime);
            Assert.AreEqual(new DateTime(2002, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry.PasswordModificationTime);
            Assert.AreEqual(new DateTime(2003, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry.LastAccessTime);
            Assert.AreEqual(new DateTime(2004, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry.PasswordExpiryTime);
            Assert.AreEqual(new DateTime(2005, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry.LastModificationTime);
            Assert.AreEqual("http://example.com", entry.Url);
            Assert.AreEqual("00-01-02-03-04-05-06-07-08-09", BitConverter.ToString(entry.TwoFactorKey));
            Assert.AreEqual("1234 5678 9012 3456", entry.CreditCardNumber);
            Assert.AreEqual("Title", entry.CreditCardExpiration);
            Assert.AreEqual("0987", entry.CreditCardVerificationValue);
            Assert.AreEqual("6543", entry.CreditCardPin);
        }

    }
}
