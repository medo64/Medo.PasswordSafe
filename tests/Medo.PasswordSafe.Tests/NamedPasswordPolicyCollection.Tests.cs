using Medo.Security.Cryptography.PasswordSafe;
using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class NamedPasswordPolicyCollection_Tests {

    [TestMethod]  // NamedPasswordPolicyCollection: New
    public void NamedPasswordPolicyCollection_New_Empty() {
        var doc = new PwSafe.Document("Password");
        doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.NamedPasswordPolicies) { Text = "" });

        PwSafe.NamedPasswordPolicyCollection passwordPolicies = new PwSafe.NamedPasswordPolicyCollection(doc);
        Assert.AreEqual(0, passwordPolicies.Count);
    }

    [TestMethod]  // NamedPasswordPolicyCollection: New a non-empty collection
    public void NamedPasswordPolicyCollection_New_NonEmpty() {
        var doc = new PwSafe.Document("Password");
        doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.NamedPasswordPolicies) { Text = "0104Test111101200100200300404@#$%" });

        PwSafe.NamedPasswordPolicyCollection passwordPolicies = new PwSafe.NamedPasswordPolicyCollection(doc);
        Assert.AreEqual(1, passwordPolicies.Count);
        PwSafe.NamedPasswordPolicy policy = passwordPolicies[0];
        Assert.AreEqual("Test", policy.Name);
        Assert.AreEqual(0x1111, (int)policy.Style);
        Assert.AreEqual(18, policy.TotalPasswordLength);
        Assert.AreEqual(1, policy.MinimumLowercaseCount);
        Assert.AreEqual(2, policy.MinimumUppercaseCount);
        Assert.AreEqual(3, policy.MinimumDigitCount);
        Assert.AreEqual(4, policy.MinimumSymbolCount);
        Assert.AreEqual(4, policy.GetSpecialSymbolSet().Length);
    }

    [TestMethod]  // NamedPasswordPolicyCollection: Clear
    public void NamedPasswordPolicyCollection_Clear() {
        var doc = new PwSafe.Document("Password");
        doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.NamedPasswordPolicies) { Text = "0104Test111101200100200300404@#$%" });

        PwSafe.NamedPasswordPolicyCollection passwordPolicies = new PwSafe.NamedPasswordPolicyCollection(doc);
        Assert.AreEqual(1, passwordPolicies.Count);
        passwordPolicies.Clear();
        Assert.AreEqual(0, passwordPolicies.Count);
    }

    [TestMethod]  // NamedPasswordPolicyCollection: Add
    public void NamedPasswordPolicyCollection_Add() {
        var doc = new PwSafe.Document("Password");
        doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.NamedPasswordPolicies) { Text = "" });

        PwSafe.NamedPasswordPolicyCollection passwordPolicies = new PwSafe.NamedPasswordPolicyCollection(doc);
        Assert.AreEqual(0, passwordPolicies.Count);

        NamedPasswordPolicy policy = new PwSafe.NamedPasswordPolicy("Test", 10) {
            Style = (PwSafe.PasswordPolicyStyle)0x111,
            MinimumLowercaseCount = 1,
            MinimumUppercaseCount = 1,
            MinimumDigitCount = 1,
            MinimumSymbolCount = 1,

        };
        policy.SetSpecialSymbolSet(['@']);
        passwordPolicies.Add(policy);
        Assert.AreEqual(1, passwordPolicies.Count);
        Assert.AreEqual("0104Test011100A00100100100101@", doc.Headers[PwSafe.HeaderType.NamedPasswordPolicies].Text);
    }

    [TestMethod]  // NamedPasswordPolicyCollection: Add (duplicate)
    public void NamedPasswordPolicyCollection_Add_Duplicate() {
        var doc = new PwSafe.Document("Password");
        doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.NamedPasswordPolicies) { Text = "0104Test111101200100200300404@#$%" });

        PwSafe.NamedPasswordPolicyCollection passwordPolicies = new PwSafe.NamedPasswordPolicyCollection(doc);
        Assert.AreEqual(1, passwordPolicies.Count);

        Exception ex = Assert.ThrowsException<ArgumentException>(() => {
            NamedPasswordPolicy policy = new PwSafe.NamedPasswordPolicy("Test", 10);
            passwordPolicies.Add(policy);
        });

        Assert.AreEqual("Password policy with the name 'Test' already existed in collection. (Parameter 'policy')", ex.Message);
    }

    [TestMethod]  // NamedPasswordPolicyCollection: AddRange
    public void NamedPasswordPolicyCollection_AddRange() {
        var doc = new PwSafe.Document("Password");
        doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.NamedPasswordPolicies) { Text = "" });

        PwSafe.NamedPasswordPolicyCollection passwordPolicies = new PwSafe.NamedPasswordPolicyCollection(doc);
        Assert.AreEqual(0, passwordPolicies.Count);

        NamedPasswordPolicy policy = new PwSafe.NamedPasswordPolicy("Test", 10) {
            Style = (PwSafe.PasswordPolicyStyle)0x111,
            MinimumLowercaseCount = 1,
            MinimumUppercaseCount = 1,
            MinimumDigitCount = 1,
            MinimumSymbolCount = 1,

        };
        policy.SetSpecialSymbolSet(['@']);
        passwordPolicies.AddRange(new List<NamedPasswordPolicy>() { policy });
        Assert.AreEqual(1, passwordPolicies.Count);
        Assert.AreEqual("0104Test011100A00100100100101@", doc.Headers[PwSafe.HeaderType.NamedPasswordPolicies].Text);
    }

    [TestMethod]  // NamedPasswordPolicyCollection: AddRange (duplicate)
    public void NamedPasswordPolicyCollection_AddRange_Duplicate() {
        var doc = new PwSafe.Document("Password");
        doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.NamedPasswordPolicies) { Text = "0104Test111101200100200300404@#$%" });

        PwSafe.NamedPasswordPolicyCollection passwordPolicies = new PwSafe.NamedPasswordPolicyCollection(doc);
        Assert.AreEqual(1, passwordPolicies.Count);

        Exception ex = Assert.ThrowsException<ArgumentException>(() => {
            NamedPasswordPolicy policy = new PwSafe.NamedPasswordPolicy("Test", 10);
            passwordPolicies.AddRange(new List<NamedPasswordPolicy>() { policy });
        });

        Assert.AreEqual("Password policy with the name 'Test' already existed in collection. (Parameter 'policies')", ex.Message);
    }

    [TestMethod]  // NamedPasswordPolicyCollection: Remove
    public void NamedPasswordPolicyCollection_Remove() {
        var doc = new PwSafe.Document("Password");
        doc.Headers.Add(new PwSafe.Header(PwSafe.HeaderType.NamedPasswordPolicies) { Text = "0104Test111101200100200300404@#$%" });

        PwSafe.NamedPasswordPolicyCollection passwordPolicies = new PwSafe.NamedPasswordPolicyCollection(doc);
        Assert.AreEqual(1, passwordPolicies.Count);

        passwordPolicies.Remove(passwordPolicies[0]);
        Assert.AreEqual(0, passwordPolicies.Count);
    }
}

