using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

using static Tests.Helpers;

namespace Tests;

[TestClass]
public class Entry_Tests {

    [TestMethod]  // Entry: New
    public void Entry_New() {
        var entry = new PwSafe.Entry();
        Assert.AreEqual(3, entry.Records.Count);
        Assert.IsTrue(entry.Records.Contains(PwSafe.RecordType.Uuid));
        Assert.IsTrue(entry.Records.Contains(PwSafe.RecordType.Title));
        Assert.IsTrue(entry.Records.Contains(PwSafe.RecordType.Password));
        Assert.IsTrue(entry.Uuid != Guid.Empty);
        Assert.AreEqual("", entry.Title);
        Assert.AreEqual("", entry.Password);
    }

    [TestMethod]  // Entry: New with Title
    public void Entry_New_WithTitle() {
        var entry = new PwSafe.Entry("Test");
        Assert.AreEqual(3, entry.Records.Count);
        Assert.IsTrue(entry.Records.Contains(PwSafe.RecordType.Uuid));
        Assert.IsTrue(entry.Records.Contains(PwSafe.RecordType.Title));
        Assert.IsTrue(entry.Records.Contains(PwSafe.RecordType.Password));
        Assert.IsTrue(entry.Uuid != Guid.Empty);
        Assert.AreEqual("Test", entry.Title);
        Assert.AreEqual("", entry.Password);
    }


    [TestMethod]  // Entry: Clone
    public void Entry_Clone() {
        var entry = new PwSafe.Entry("Test");
        Assert.AreEqual(3, entry.Records.Count);
        Assert.IsTrue(entry.Records.Contains(PwSafe.RecordType.Uuid));
        Assert.IsTrue(entry.Records.Contains(PwSafe.RecordType.Title));
        Assert.IsTrue(entry.Records.Contains(PwSafe.RecordType.Password));
        Assert.IsTrue(entry.Uuid != Guid.Empty);
        Assert.AreEqual("Test", entry.Title);
        Assert.AreEqual("", entry.Password);

        var clone = entry.Clone();
        Assert.AreEqual(3, clone.Records.Count);
        Assert.IsTrue(clone.Records.Contains(PwSafe.RecordType.Uuid));
        Assert.IsTrue(clone.Records.Contains(PwSafe.RecordType.Title));
        Assert.IsTrue(clone.Records.Contains(PwSafe.RecordType.Password));
        Assert.IsTrue(clone.Uuid != Guid.Empty);
        Assert.AreEqual("Test", clone.Title);
        Assert.AreEqual("", clone.Password);
    }

    [TestMethod]  // Entry: Clone (in document)
    public void Entry_Clone_Document() {
        var doc = new PwSafe.Document("Password");
        doc.Entries.Add(new PwSafe.Entry("Test"));
        doc.Save(new MemoryStream());

        doc.Entries[0].Clone();
        Assert.IsFalse(doc.HasChanged);
    }


    [TestMethod]  // Entry: Change (read-only)
    public void Entry_ReadOnly() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var doc = new PwSafe.Document("Password");
            doc.Entries["Test"].Password = "Old";

            doc.IsReadOnly = true;
            doc.Entries["Test"].Password = "New";
        });
    }


    [TestMethod]  // Entry: Indexer Get via Type
    public void Entry_AccessByRecordType() {
        var doc = new PwSafe.Document("Password");

        doc.Entries["Test"].Password = "Old";
        Assert.IsTrue(doc.Entries["Test"][PwSafe.RecordType.Uuid].Uuid != Guid.Empty);
        Assert.AreEqual("Old", doc.Entries["Test"][PwSafe.RecordType.Password].Text);

        doc.Entries["Test"][PwSafe.RecordType.Password].Text = "New";
        Assert.AreEqual("New", doc.Entries["Test"][PwSafe.RecordType.Password].Text);
    }


    [TestMethod]  // Entry: Add
    public void Entry_TestNamed() {
        var guid = Guid.NewGuid();

        var doc = new PwSafe.Document("Password") { TrackAccess = false, TrackModify = false };
        var entry = new PwSafe.Entry();
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
        entry.SetTwoFactorKey([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
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

        Assert.AreEqual(guid, entry[PwSafe.RecordType.Uuid].Uuid);
        Assert.AreEqual("Group", entry[PwSafe.RecordType.Group].Text);
        Assert.AreEqual("Title", entry[PwSafe.RecordType.Title].Text);
        Assert.AreEqual("UserName", entry[PwSafe.RecordType.UserName].Text);
        Assert.AreEqual("Notes", entry[PwSafe.RecordType.Notes].Text);
        Assert.AreEqual("Password", entry[PwSafe.RecordType.Password].Text);
        Assert.AreEqual(new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[PwSafe.RecordType.CreationTime].Time);
        Assert.AreEqual(new DateTime(2002, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[PwSafe.RecordType.PasswordModificationTime].Time);
        Assert.AreEqual(new DateTime(2003, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[PwSafe.RecordType.LastAccessTime].Time);
        Assert.AreEqual(new DateTime(2004, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[PwSafe.RecordType.PasswordExpiryTime].Time);
        Assert.AreEqual(new DateTime(2005, 1, 1, 0, 0, 0, DateTimeKind.Utc), entry[PwSafe.RecordType.LastModificationTime].Time);
        Assert.AreEqual("http://example.com", entry[PwSafe.RecordType.Url].Text);
        Assert.AreEqual("example@example.com", entry[PwSafe.RecordType.EmailAddress].Text);
        Assert.AreEqual("00-01-02-03-04-05-06-07-08-09", BitConverter.ToString(entry[PwSafe.RecordType.TwoFactorKey].GetBytes()));
        Assert.AreEqual("1234 5678 9012 3456", entry[PwSafe.RecordType.CreditCardNumber].Text);
        Assert.AreEqual("Title", entry[PwSafe.RecordType.CreditCardExpiration].Text);
        Assert.AreEqual("0987", entry[PwSafe.RecordType.CreditCardVerificationValue].Text);
        Assert.AreEqual("6543", entry[PwSafe.RecordType.CreditCardPin].Text);
        Assert.AreEqual("https://medo64.com/", entry[PwSafe.RecordType.QRCode].Text);
    }



    [TestMethod]  // Entry: Autotype (default tokens)
    public void Entry_Autotype_Tokens_Default() {
        Assert.AreEqual("UserName {Tab} Password {Enter}", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(null)));
        Assert.AreEqual("D e f a u l t {Tab} P a s s w 0 r d {Enter}", string.Join(" ", GetExampleEntry(null).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (two-factor)
    public void Entry_Autotype_Tokens_TwoFactor() {
        var autoTypeText = @"\u\t\p\t\2\t\n";
        Assert.AreEqual("UserName {Tab} Password {Tab} TwoFactorCode {Tab} {Enter}", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("D e f a u l t {Tab} P a s s w 0 r d {Tab} TwoFactorCode {Tab} {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype (some text)
    public void Entry_Autotype_Tokens_SomeText1() {
        var autoTypeText = @"admin\n\p\n";
        Assert.AreEqual("a d m i n {Enter} Password {Enter}", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("a d m i n {Enter} P a s s w 0 r d {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (some text 2)
    public void Entry_Autotype_Tokens_SomeText2() {
        var autoTypeText = @"\badmin\n\p\n";
        Assert.AreEqual("{Backspace} a d m i n {Enter} Password {Enter}", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("{Backspace} a d m i n {Enter} P a s s w 0 r d {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (some text 3)
    public void Entry_Autotype_Tokens_SomeText3() {
        var autoTypeText = @"admin\n\p\nXXX";
        Assert.AreEqual("a d m i n {Enter} Password {Enter} X X X", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("a d m i n {Enter} P a s s w 0 r d {Enter} X X X", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype (credit card)
    public void Entry_Autotype_Tokens_CreditCard() {
        var autoTypeText = @"\cn\t\ce\t\cv\t\cp";
        Assert.AreEqual("CreditCardNumber {Tab} CreditCardExpiration {Tab} CreditCardVerificationValue {Tab} CreditCardPin", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 {Tab} 0 1 / 7 9 {Tab} 1 2 3 {Tab} 1 2 3 4", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (credit card, tabbed)
    public void Entry_Autotype_Tokens_CreditCardTabbed() {
        var autoTypeText = @"\ct\t\ce\t\cv\t\cp";
        Assert.AreEqual("CreditCardNumberTabbed {Tab} CreditCardExpiration {Tab} CreditCardVerificationValue {Tab} CreditCardPin", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("1 2 3 4 {Tab} 5 6 7 8 {Tab} 9 0 1 2 {Tab} 3 4 5 6 {Tab} 0 1 / 7 9 {Tab} 1 2 3 {Tab} 1 2 3 4", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (credit card, tabbed Amex)
    public void Entry_Autotype_Tokens_CreditCardTabbedAmex() {
        var autoTypeText = @"\ct\t\ce\t\cv\t\cp";
        Assert.AreEqual("CreditCardNumberTabbed {Tab} CreditCardExpiration {Tab} CreditCardVerificationValue {Tab} CreditCardPin", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("1 2 3 {Tab} 4 5 6 7 {Tab} 8 9 0 1 {Tab} 2 3 4 5 {Tab} 0 1 / 7 9 {Tab} 1 2 3 {Tab} 1 2 3 4", string.Join(" ", GetExampleEntry(autoTypeText, amexCard: true).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype (optional number, not used)
    public void Entry_Autotype_Tokens_OptionalNumberNotUsed() {
        var autoTypeText = @"\oTest";
        Assert.AreEqual("Notes T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("1 {Enter} 2 {Enter} 3 {Enter} {^} {Enter} T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype (optional number, line 1)
    public void Entry_Autotype_Tokens_OptionalNumber_Line1() {
        var autoTypeText = @"\o1Test";
        Assert.AreEqual("Notes:1 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("1 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (optional number, line 2)
    public void Entry_Autotype_Tokens_OptionalNumber_Line2() {
        var autoTypeText = @"\o2Test";
        Assert.AreEqual("Notes:2 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("2 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (optional number, line 3)
    public void Entry_Autotype_Tokens_OptionalNumber_Line3() {
        var autoTypeText = @"\o3Test";
        Assert.AreEqual("Notes:3 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("3 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (optional number, line 4)
    public void Entry_Autotype_Tokens_OptionalNumber_Line4() {
        var autoTypeText = @"\o4Test";
        Assert.AreEqual("Notes:4 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("{^} T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (optional number, line 5)
    public void Entry_Autotype_Tokens_OptionalNumber_Line5() {
        var autoTypeText = @"\o5Test";
        Assert.AreEqual("Notes:5 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype (optional number, single digit)
    public void Entry_Autotype_Tokens_OptionalNumberOneDigit() {
        var autoTypeText = @"\o9Test";
        Assert.AreEqual("Notes:9 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (optional number, two digit)
    public void Entry_Autotype_Tokens_OptionalNumberTwoDigits() {
        var autoTypeText = @"\o98Test";
        Assert.AreEqual("Notes:98 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (optional number, three digits)
    public void Entry_Autotype_Tokens_OptionalNumberThreeDigits() {
        var autoTypeText = @"\o987Test";
        Assert.AreEqual("Notes:987 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype (optional number, no suffix)
    public void Entry_Autotype_Tokens_OptionalNumberNoSuffix() {
        var autoTypeText = @"\o12";
        Assert.AreEqual("Notes:12", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype (mandatory number, single digit)
    public void Entry_Autotype_Tokens_MandatoryNumberOneDigit() {
        var autoTypeText = @"\W1Test";
        Assert.AreEqual("Wait:1000 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("Wait:1000 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (mandatory number, two digits)
    public void Entry_Autotype_Tokens_MandatoryNumberTwoDigit() {
        var autoTypeText = @"\w12Test";
        Assert.AreEqual("Wait:12 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("Wait:12 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (mandatory number, three digits)
    public void Entry_Autotype_Tokens_MandatoryNumberThreeDigit() {
        var autoTypeText = @"\d123Test";
        Assert.AreEqual("Delay:123 T e s t", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("Delay:123 T e s t", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (mandatory number, no suffix)
    public void Entry_Autotype_Tokens_MandatoryNumberNoSuffix() {
        var autoTypeText = @"\d12";
        Assert.AreEqual("Delay:12", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("Delay:12", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype (example 1)
    public void Entry_Autotype_Tokens_Example1() {
        var autoTypeText = @"\z\u\t\p\n";
        Assert.AreEqual("Legacy UserName {Tab} Password {Enter}", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("Legacy D e f a u l t {Tab} P a s s w 0 r d {Enter}", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype (example 2)
    public void Entry_Autotype_Tokens_Example2() {
        var autoTypeText = @"\i\g\l\m";
        Assert.AreEqual("Title Group Url Email", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("E x a m p l e E x a m p l e s m e d o 6 4 . c o m t e s t @ e x a m p l e . c o m", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    #region Typos

    [TestMethod]  // Entry: Autotype typo (no escape)
    public void Entry_Autotype_Tokens_TypoNoEscape() {
        var autoTypeText = @"\x";
        Assert.AreEqual("x", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("x", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype typo (no escape, two char)
    public void Entry_Autotype_Tokens_TypoNoEscapeDouble() {
        var autoTypeText = @"\cx\p";
        Assert.AreEqual("c x Password", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual("c x P a s s w 0 r d", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype typo (no escape, hanging escape)
    public void Entry_Autotype_Tokens_HangingEscape() {
        var autoTypeText = @"admin\";
        Assert.AreEqual(@"a d m i n \", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual(@"a d m i n \", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype typo (optional number, too long)
    public void Entry_Autotype_Tokens_OptionalNumberTooLong() {
        var autoTypeText = @"\o1234";
        Assert.AreEqual(@"Notes:123 4", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual(@"4", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }


    [TestMethod]  // Entry: Autotype typo (mandatory number, too long)
    public void Entry_Autotype_Tokens_MandatoryNumberTooLong() {
        var autoTypeText = @"\w1234";
        Assert.AreEqual(@"Wait:123 4", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual(@"Wait:123 4", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype typo (mandatory number, invalid number)
    public void Entry_Autotype_Tokens_MandatoryNumberNotPresent() {
        var autoTypeText = @"\dX";
        Assert.AreEqual(@"d X", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual(@"d X", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    [TestMethod]  // Entry: Autotype typo (mandatory number, no number)
    public void Entry_Autotype_Tokens_MandatoryIncompleteCommand() {
        var autoTypeText = @"\W";
        Assert.AreEqual(@"W", string.Join(" ", PwSafe.AutotypeToken.GetUnexpandedAutotypeTokens(autoTypeText)));
        Assert.AreEqual(@"W", string.Join(" ", GetExampleEntry(autoTypeText).AutotypeTokens));
    }

    #endregion

}
