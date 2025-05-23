using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class NamedPasswordPolicy_Tests {

    [TestMethod]  // NamedPasswordPolicy: New
    public void NamedPasswordPolicy_New() {
        var policy = new PwSafe.NamedPasswordPolicy("Test", 10) {
            Style = PwSafe.PasswordPolicyStyle.MakePronounceable,
            MinimumLowercaseCount = 1,
            MinimumUppercaseCount = 2,
            MinimumDigitCount = 3,
            MinimumSymbolCount = 4
        };
        Assert.AreEqual("Test", policy.Name);
        Assert.AreEqual(0x0200, (int)policy.Style);
        Assert.AreEqual(10, policy.TotalPasswordLength);
        Assert.AreEqual(1, policy.MinimumLowercaseCount);
        Assert.AreEqual(2, policy.MinimumUppercaseCount);
        Assert.AreEqual(3, policy.MinimumDigitCount);
        Assert.AreEqual(4, policy.MinimumSymbolCount);
        Assert.AreEqual("", new string(policy.GetSpecialSymbolSet()));
        Assert.AreEqual("Test", policy.ToString());
    }


    [TestMethod]  // NamedPasswordPolicy: Single special symbols
    public void NamedPasswordPolicy_SingleSymbol() {
        var policy = new PwSafe.NamedPasswordPolicy("Test", 10);
        policy.SetSpecialSymbolSet(new char[] { '!' });
        Assert.AreEqual("!", new string(policy.GetSpecialSymbolSet()));
    }

    [TestMethod]  // NamedPasswordPolicy: Filter duplicate symbols
    public void NamedPasswordPolicy_DuplicateSymbols() {
        var policy = new PwSafe.NamedPasswordPolicy("Test", 10);
        policy.SetSpecialSymbolSet(new char[] { 'A', 'B', 'B', 'A', 'a', 'b', 'b', 'a' });
        Assert.AreEqual("ABab", new string(policy.GetSpecialSymbolSet()));
    }

    [TestMethod]  // NamedPasswordPolicy: Empty special symbols
    public void NamedPasswordPolicy_EmptySymbols() {
        var policy = new PwSafe.NamedPasswordPolicy("Test", 10);
        policy.SetSpecialSymbolSet(new char[] { '!' });
        policy.SetSpecialSymbolSet();
        Assert.AreEqual("", new string(policy.GetSpecialSymbolSet()));
    }

}
