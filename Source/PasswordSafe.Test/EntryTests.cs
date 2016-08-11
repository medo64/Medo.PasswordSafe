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
            entry.Email = "example@example.com";
            entry.TwoFactorKey = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            entry.CreditCardNumber = "1234 5678 9012 3456";
            entry.CreditCardExpiration = "Title";
            entry.CreditCardVerificationValue = "0987";
            entry.CreditCardPin = "6543";
            entry.QRCode = "https://medo64.com/";

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
            Assert.AreEqual("example@example.com", entry.Email);
            Assert.AreEqual("00-01-02-03-04-05-06-07-08-09", BitConverter.ToString(entry.TwoFactorKey));
            Assert.AreEqual("1234 5678 9012 3456", entry.CreditCardNumber);
            Assert.AreEqual("Title", entry.CreditCardExpiration);
            Assert.AreEqual("0987", entry.CreditCardVerificationValue);
            Assert.AreEqual("6543", entry.CreditCardPin);
            Assert.AreEqual("https://medo64.com/", entry.QRCode);

            Assert.AreEqual(guid, entry[RecordType.Uuid].Uuid);
            Assert.AreEqual("Group", entry[RecordType.Group].Text);
            Assert.AreEqual("Title", entry[RecordType.Title].Text);
            Assert.AreEqual("UserName", entry[RecordType.UserName].Text);
            Assert.AreEqual("Notes", entry[RecordType.Notes].Text);
            Assert.AreEqual("Password", entry[RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[RecordType.CreationTime].Time);
            Assert.AreEqual(new DateTime(2002, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[RecordType.PasswordModificationTime].Time);
            Assert.AreEqual(new DateTime(2003, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[RecordType.LastAccessTime].Time);
            Assert.AreEqual(new DateTime(2004, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[RecordType.PasswordExpiryTime].Time);
            Assert.AreEqual(new DateTime(2005, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[RecordType.LastModificationTime].Time);
            Assert.AreEqual("http://example.com", entry[RecordType.Url].Text);
            Assert.AreEqual("example@example.com", entry[RecordType.EmailAddress].Text);
            Assert.AreEqual("00-01-02-03-04-05-06-07-08-09", BitConverter.ToString(entry[RecordType.TwoFactorKey].GetBytes()));
            Assert.AreEqual("1234 5678 9012 3456", entry[RecordType.CreditCardNumber].Text);
            Assert.AreEqual("Title", entry[RecordType.CreditCardExpiration].Text);
            Assert.AreEqual("0987", entry[RecordType.CreditCardVerificationValue].Text);
            Assert.AreEqual("6543", entry[RecordType.CreditCardPin].Text);
            Assert.AreEqual("https://medo64.com/", entry[RecordType.QRCode].Text);
        }



        [TestMethod]
        public void Entry_Autotype_Tokens_Default() {
            Assert.AreEqual("UserName {Tab} Password {Tab} {Enter}", string.Join(" ", GetExampleEntry(null).RawAutotypeTokens));
            Assert.AreEqual("D e f a u l t {Tab} P a s s w 0 r d {Tab} {Enter}", string.Join(" ", GetExampleEntry(null).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_TwoFactor() {
            var autoTypeText = @"\u\t\p\t\2\t\n";
            Assert.AreEqual("UserName {Tab} Password {Tab} TwoFactorCode {Tab} {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("D e f a u l t {Tab} P a s s w 0 r d {Tab} TwoFactorCode {Tab} {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_SomeText1() {
            var autoTypeText = @"admin\n\p\n";
            Assert.AreEqual("a d m i n {Enter} Password {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("a d m i n {Enter} P a s s w 0 r d {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_SomeText2() {
            var autoTypeText = @"\badmin\n\p\n";
            Assert.AreEqual("{Backspace} a d m i n {Enter} Password {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("{Backspace} a d m i n {Enter} P a s s w 0 r d {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_SomeText3() {
            var autoTypeText = @"admin\n\p\nXXX";
            Assert.AreEqual("a d m i n {Enter} Password {Enter} X X X", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("a d m i n {Enter} P a s s w 0 r d {Enter} X X X", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_CreditCard() {
            var autoTypeText = @"\cn\t\ce\t\cv\t\cp";
            Assert.AreEqual("CreditCardNumber {Tab} CreditCardExpiration {Tab} CreditCardVerificationValue {Tab} CreditCardPin", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 {Tab} 0 1 / 7 9 {Tab} 1 2 3 {Tab} 1 2 3 4", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumberNotUsed() {
            var autoTypeText = @"\oTest";
            Assert.AreEqual("Notes T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("1 {Enter} 2 {Enter} 3 {Enter} {^} {Enter} T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumber_Line1() {
            var autoTypeText = @"\o1Test";
            Assert.AreEqual("Notes:1 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("1 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumber_Line2() {
            var autoTypeText = @"\o2Test";
            Assert.AreEqual("Notes:2 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("2 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumber_Line3() {
            var autoTypeText = @"\o3Test";
            Assert.AreEqual("Notes:3 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("3 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumber_Line4() {
            var autoTypeText = @"\o4Test";
            Assert.AreEqual("Notes:4 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("{^} T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumber_Line5() {
            var autoTypeText = @"\o5Test";
            Assert.AreEqual("Notes:5 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumberOneDigit() {
            var autoTypeText = @"\o9Test";
            Assert.AreEqual("Notes:9 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumberTwoDigits() {
            var autoTypeText = @"\o98Test";
            Assert.AreEqual("Notes:98 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumberThreeDigits() {
            var autoTypeText = @"\o987Test";
            Assert.AreEqual("Notes:987 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumberNoSuffix() {
            var autoTypeText = @"\o12";
            Assert.AreEqual("Notes:12", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_MandatoryNumberOneDigit() {
            var autoTypeText = @"\W1Test";
            Assert.AreEqual("Wait:1000 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("Wait:1000 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_MandatoryNumberTwoDigit() {
            var autoTypeText = @"\w12Test";
            Assert.AreEqual("Wait:12 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("Wait:12 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_MandatoryNumberThreeDigit() {
            var autoTypeText = @"\d123Test";
            Assert.AreEqual("Delay:123 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("Delay:123 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_MandatoryNumberNoSuffix() {
            var autoTypeText = @"\d12";
            Assert.AreEqual("Delay:12", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("Delay:12", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_Example1() {
            var autoTypeText = @"\z\u\t\p\n";
            Assert.AreEqual("Legacy UserName {Tab} Password {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("Legacy D e f a u l t {Tab} P a s s w 0 r d {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_Example2() {
            var autoTypeText = @"\i\g\l\m";
            Assert.AreEqual("Title Group Url Email", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("E x a m p l e E x a m p l e s m e d o 6 4 . c o m t e s t @ e x a m p l e . c o m", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        #region Typos

        [TestMethod]
        public void Entry_Autotype_Tokens_TypoNoEscape() {
            var autoTypeText = @"\x";
            Assert.AreEqual("x", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("x", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_TypoNoEscapeDouble() {
            var autoTypeText = @"\cx\p";
            Assert.AreEqual("c x Password", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual("c x P a s s w 0 r d", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_HangingEscape() {
            var autoTypeText = @"admin\";
            Assert.AreEqual(@"a d m i n \", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual(@"a d m i n \", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_OptionalNumberTooLong() {
            var autoTypeText = @"\o1234";
            Assert.AreEqual(@"Notes:123 4", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual(@"4", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        [TestMethod]
        public void Entry_Autotype_Tokens_MandatoryNumberTooLong() {
            var autoTypeText = @"\w1234";
            Assert.AreEqual(@"Wait:123 4", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual(@"Wait:123 4", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_MandatoryNumberNotPresent() {
            var autoTypeText = @"\dX";
            Assert.AreEqual(@"d X", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual(@"d X", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }

        [TestMethod]
        public void Entry_Autotype_Tokens_MandatoryIncompleteCommand() {
            var autoTypeText = @"\W";
            Assert.AreEqual(@"W", string.Join(" ", GetExampleEntry(autoTypeText).RawAutotypeTokens));
            Assert.AreEqual(@"W", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
        }


        private static Entry GetExampleEntry(string autotypeText) {
            var entry = new Entry() {
                Title = "Example",
                Group = "Examples",
                UserName = "Default",
                Password = "Passw0rd",
                CreditCardNumber = "1234567890123456",
                CreditCardExpiration = "01/79",
                CreditCardVerificationValue = "123",
                CreditCardPin = "1234",
                TwoFactorKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 },
                Email = "test@example.com",
                Url = "medo64.com",
                Notes = "1\r\n2\n3\r^\n",
            };
            if (autotypeText != null) { entry.Autotype = autotypeText; }
            return entry;
        }

        #endregion

    }
}
