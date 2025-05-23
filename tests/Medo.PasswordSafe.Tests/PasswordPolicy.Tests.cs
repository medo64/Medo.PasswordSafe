using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class PasswordPolicy_Tests {

    [TestMethod]  // PasswordPolicy: New
    public void PasswordPolicy_New() {
        var policy = new PwSafe.PasswordPolicy(10) {
            Style = PwSafe.PasswordPolicyStyle.MakePronounceable,
            MinimumLowercaseCount = 1,
            MinimumUppercaseCount = 2,
            MinimumDigitCount = 3,
            MinimumSymbolCount = 4
        };
        Assert.AreEqual(0x0200, (int)policy.Style);
        Assert.AreEqual(10, policy.TotalPasswordLength);
        Assert.AreEqual(1, policy.MinimumLowercaseCount);
        Assert.AreEqual(2, policy.MinimumUppercaseCount);
        Assert.AreEqual(3, policy.MinimumDigitCount);
        Assert.AreEqual(4, policy.MinimumSymbolCount);
        Assert.AreEqual("", new string(policy.GetSpecialSymbolSet()));
    }


    [TestMethod]  // PasswordPolicy: Single special symbols
    public void PasswordPolicy_SingleSymbol() {
        var policy = new PwSafe.PasswordPolicy(10);
        policy.SetSpecialSymbolSet(new char[] { '!' });
        Assert.AreEqual("!", new string(policy.GetSpecialSymbolSet()));
    }

    [TestMethod]  // PasswordPolicy: Filter duplicate symbols
    public void PasswordPolicy_DuplicateSymbols() {
        var policy = new PwSafe.PasswordPolicy(10);
        policy.SetSpecialSymbolSet(new char[] { 'A', 'B', 'B', 'A', 'a', 'b', 'b', 'a' });
        Assert.AreEqual("ABab", new string(policy.GetSpecialSymbolSet()));
    }

    [TestMethod]  // PasswordPolicy: Empty special symbols
    public void PasswordPolicy_EmptySymbols() {
        var policy = new PwSafe.PasswordPolicy(10);
        policy.SetSpecialSymbolSet(new char[] { '!' });
        policy.SetSpecialSymbolSet();
        Assert.AreEqual("", new string(policy.GetSpecialSymbolSet()));
    }

}
