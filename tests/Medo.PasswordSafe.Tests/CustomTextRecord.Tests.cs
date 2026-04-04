using System;
using System.Text;
using System.Text.Unicode;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class CustomTextRecord_Tests {

    [TestMethod]
    public void CustomTextRecord_NonSensitive() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("010009WiFi SSID020004Test")) { };
        Assert.AreEqual("WiFi SSID", field.Caption);
        Assert.AreEqual("Test", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_Sensitive() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("01000DWiFi Password02000Dbobsyouruncle0300011")) { };
        Assert.AreEqual("WiFi Password", field.Caption);
        Assert.AreEqual("bobsyouruncle", field.Text);
        Assert.AreEqual(true, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_OnlyParseTheFirst() {  // didn't implement parsing of all entries, just take the first
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("010009WiFi SSID020004Test00000001000DWiFi Password02000Dbobsyouruncle0300011")) { };
        Assert.AreEqual("WiFi SSID", field.Caption);
        Assert.AreEqual("Test", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_CaptionTypeTooShort() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("0"));
        Assert.AreEqual("", field.Caption);
        Assert.AreEqual("", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_CaptionLengthTooShort() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("01000"));
        Assert.AreEqual("", field.Caption);
        Assert.AreEqual("", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_CaptionContentTooShort() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("010009WiFi SSI"));
        Assert.AreEqual("", field.Caption);
        Assert.AreEqual("", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }


    [TestMethod]
    public void CustomTextRecord_TextTypeTooShort() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("010009WiFi SSID0"));
        Assert.AreEqual("WiFi SSID", field.Caption);
        Assert.AreEqual("", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_TextLengthTooShort() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("010009WiFi SSID02000"));
        Assert.AreEqual("WiFi SSID", field.Caption);
        Assert.AreEqual("", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_TextContentTooShort() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("010009WiFi SSID020004Tes"));
        Assert.AreEqual("WiFi SSID", field.Caption);
        Assert.AreEqual("", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_SensitiveTypeTooShort() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("010009WiFi SSID020004Test0"));
        Assert.AreEqual("WiFi SSID", field.Caption);
        Assert.AreEqual("Test", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_SensitiveLengthTooShort() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("010009WiFi SSID020004Test0000000"));
        Assert.AreEqual("WiFi SSID", field.Caption);
        Assert.AreEqual("Test", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

    [TestMethod]
    public void CustomTextRecord_SensitiveContentTooShort() {
        var field = new PwSafe.CustomTextRecord(ASCIIEncoding.ASCII.GetBytes("010009WiFi SSID020004Test00000001"));
        Assert.AreEqual("WiFi SSID", field.Caption);
        Assert.AreEqual("Test", field.Text);
        Assert.AreEqual(false, field.IsSensitive);
    }

}
