using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

using static Tests.Helpers;

namespace Tests;

[TestClass]
public class Document_Tests {

    [TestMethod] // Document: Load Empty.psafe3
    public void Document_Empty() {
        using var doc = PwSafe.Document.Load(GetResourceStream("Empty.psafe3"), "123");
        Assert.AreEqual(7, doc.Headers.Count);
        Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
        Assert.AreEqual(new Guid("3b872b47-dee9-4c4f-ba63-4d93a86dfa4c"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
        Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
        Assert.AreEqual(new DateTime(2015, 12, 28, 5, 57, 23, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
        Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
        Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
        Assert.AreEqual("Password Safe V3.37", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);

        Assert.AreEqual(0, doc.Entries.Count);
    }

    [TestMethod]  // Document: Load Empty.psafe3 (password mismatch)
    public void Document_Empty_PasswordMismatch() {
        Assert.ThrowsException<FormatException>(() => {
            using var doc = PwSafe.Document.Load(GetResourceStream("Empty.psafe3"), "XXX");
        });
    }


    [TestMethod]  // Document: Load/Save Simple.psafe3"
    public void Document_Simple() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Password Safe V3.37", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);
            Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("A123", doc.Entries[0].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("B123", doc.Entries[1].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.IsFalse(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Password Safe V3.37", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);
            Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("A123", doc.Entries[0].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("B123", doc.Entries[1].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save Simple.bimil
    public void Document_SimpleBimil() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Simple.bimil"), "123")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2019, 03, 08, 04, 27, 29, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Bimil V2.70", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);
            Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("A123", doc.Entries[0].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("B123", doc.Entries[1].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.IsFalse(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2019, 03, 08, 04, 27, 29, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Bimil V2.70", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);
            Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("A123", doc.Entries[0].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("B123", doc.Entries[1].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.IsFalse(doc.HasChanged);
        }
    }


    [TestMethod]  // Document: Load/Save Simple.bimil from key
    public void Document_SimpleBimilFromKey() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.LoadWithKey(GetResourceStream("Simple.bimil"), new byte[] { 0x98, 0x33, 0x9C, 0x6D, 0xE6, 0xCF, 0x5A, 0x35, 0x53, 0x36, 0x7D, 0xFE, 0xF2, 0xC9, 0xDB, 0x1A, 0xAC, 0x28, 0xBD, 0x60, 0xFB, 0xA3, 0x9C, 0x37, 0x38, 0x4C, 0x93, 0xE6, 0x63, 0x51, 0xFE, 0xF8, 0x75, 0x45, 0x5F, 0xCD, 0x8D, 0xC3, 0x93, 0xC2, 0x1C, 0xB9, 0x14, 0xF1, 0x8E, 0xAA, 0x70, 0x49, 0xBA, 0xDE, 0xEC, 0xFB, 0x50, 0xCA, 0x65, 0x35, 0x06, 0x3E, 0x09, 0x0A, 0xE4, 0xE0, 0xFC, 0xB9 })) {
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2019, 03, 08, 04, 27, 29, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Bimil V2.70", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);
            Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("A123", doc.Entries[0].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("B123", doc.Entries[1].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.IsFalse(doc.HasChanged);
            Assert.ThrowsException<NotSupportedException>(() => {
                doc.Save(msSave);
            });

            doc.SetPassphrase("123");
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2019, 03, 08, 04, 27, 29, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Bimil V2.70", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);
            Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("A123", doc.Entries[0].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("B123", doc.Entries[1].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save Simple.bimil using key
    public void Document_SimpleBimilToKey() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Simple.bimil"), "123")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;
            doc.SaveWithKey(msSave, new byte[] { 0x11, 0x22, 0x33, 0x6D, 0xE6, 0xCF, 0x5A, 0x35, 0x53, 0x36, 0x7D, 0xFE, 0xF2, 0xC9, 0xDB, 0x1A, 0xAC, 0x28, 0xBD, 0x60, 0xFB, 0xA3, 0x9C, 0x37, 0x38, 0x4C, 0x93, 0xE6, 0x63, 0x51, 0xFE, 0xF8, 0x75, 0x45, 0x5F, 0xCD, 0x8D, 0xC3, 0x93, 0xC2, 0x1C, 0xB9, 0x14, 0xF1, 0x8E, 0xAA, 0x70, 0x49, 0xBA, 0xDE, 0xEC, 0xFB, 0x50, 0xCA, 0x65, 0x35, 0x06, 0x3E, 0x09, 0x0A, 0xE4, 0x11, 0x22, 0x33 });
        }

        msSave.Position = 0;
        using (var doc = PwSafe.Document.LoadWithKey(msSave, new byte[] { 0x11, 0x22, 0x33, 0x6D, 0xE6, 0xCF, 0x5A, 0x35, 0x53, 0x36, 0x7D, 0xFE, 0xF2, 0xC9, 0xDB, 0x1A, 0xAC, 0x28, 0xBD, 0x60, 0xFB, 0xA3, 0x9C, 0x37, 0x38, 0x4C, 0x93, 0xE6, 0x63, 0x51, 0xFE, 0xF8, 0x75, 0x45, 0x5F, 0xCD, 0x8D, 0xC3, 0x93, 0xC2, 0x1C, 0xB9, 0x14, 0xF1, 0x8E, 0xAA, 0x70, 0x49, 0xBA, 0xDE, 0xEC, 0xFB, 0x50, 0xCA, 0x65, 0x35, 0x06, 0x3E, 0x09, 0x0A, 0xE4, 0x11, 0x22, 0x33 })) { //reload to verify key
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2019, 03, 08, 04, 27, 29, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Bimil V2.70", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);
            Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("A123", doc.Entries[0].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("B123", doc.Entries[1].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;
        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify password
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2019, 03, 08, 04, 27, 29, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Bimil V2.70", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);
            Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("A123", doc.Entries[0].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("B123", doc.Entries[1].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.IsFalse(doc.HasChanged);
        }
    }


    [TestMethod]  // Document: Load/Save Simple.psafe3 (track modify)
    public void Document_Simple_TrackModify() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
            doc.TrackAccess = false;

            doc.Headers.Remove(PwSafe.HeaderType.NonDefaultPreferences);
            doc.Headers.Remove(PwSafe.HeaderType.RecentlyUsedEntries);
            var x = doc.Entries[0].Password; //just access
            doc.Entries["B"].Notes = "Notes";

            Assert.IsTrue(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(6, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Uuid);
            Assert.IsTrue((DateTime.UtcNow >= doc.LastSaveTime) && (doc.LastSaveTime > DateTime.MinValue));
            Assert.IsTrue(doc.LastSaveUser.Length > 0);
            Assert.IsTrue(doc.LastSaveHost.Length > 0);
            Assert.AreNotEqual("Password Safe V3.37", doc.LastSaveApplication);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Title);
            Assert.AreEqual("A123", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.AreEqual(6, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Title);
            Assert.AreEqual("B123", doc.Entries[1].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime);
            Assert.IsTrue((DateTime.UtcNow >= doc.Entries[1].LastModificationTime) && (doc.Entries[1].LastModificationTime > DateTime.MinValue));
            Assert.AreEqual("Notes", doc.Entries[1].Notes);

            Assert.IsFalse(doc.HasChanged);
        }
    }


    [TestMethod]  // Document: Load/Save Simple.psafe3 (track read bytes)
    public void Document_Simple_TrackAccess_ReadBytes() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
            doc.TrackModify = false;

            doc.Headers.Remove(PwSafe.HeaderType.NonDefaultPreferences);
            doc.Headers.Remove(PwSafe.HeaderType.RecentlyUsedEntries);
            var x = doc.Entries[0].Records[PwSafe.RecordType.Password].GetBytes(); //just access

            Assert.IsTrue(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(6, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Uuid);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(5, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Title);
            Assert.AreEqual("A123", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].CreationTime);
            Assert.IsTrue((DateTime.UtcNow >= doc.Entries[0].LastAccessTime) && (doc.Entries[0].Records.Contains(PwSafe.RecordType.LastAccessTime)));

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Title);
            Assert.AreEqual("B123", doc.Entries[1].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save Simple.psafe3 (don't track silently read bytes)
    public void Document_Simple_TrackAccess_ReadBytesSilently() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
            doc.TrackModify = false;

            doc.Headers.Remove(PwSafe.HeaderType.NonDefaultPreferences);
            doc.Headers.Remove(PwSafe.HeaderType.RecentlyUsedEntries);
            var x = doc.Entries[0].Records[PwSafe.RecordType.Password].GetBytesSilently(); //just access

            Assert.IsTrue(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(6, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Uuid);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Title);
            Assert.AreEqual("A123", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Title);
            Assert.AreEqual("B123", doc.Entries[1].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save Simple.psafe3 (track access)
    public void Document_Simple_TrackAccess() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
            doc.TrackModify = false;

            doc.Headers.Remove(PwSafe.HeaderType.NonDefaultPreferences);
            doc.Headers.Remove(PwSafe.HeaderType.RecentlyUsedEntries);
            var x = doc.Entries[0].Password; //just access
            doc.Entries["B"].Notes = "Notes";

            Assert.IsTrue(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(6, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Uuid);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(5, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Title);
            Assert.AreEqual("A123", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].CreationTime);
            Assert.IsTrue((DateTime.UtcNow >= doc.Entries[0].LastAccessTime) && (doc.Entries[0].Records.Contains(PwSafe.RecordType.LastAccessTime)));

            Assert.AreEqual(5, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Title);
            Assert.AreEqual("B123", doc.Entries[1].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime);
            Assert.AreEqual("Notes", doc.Entries[1].Notes);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save Simple.psafe3 (track access and modify)
    public void Document_Simple_TrackAccessAndModify() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
            doc.Headers.Remove(PwSafe.HeaderType.NonDefaultPreferences);
            doc.Headers.Remove(PwSafe.HeaderType.RecentlyUsedEntries);
            var x = doc.Entries[0].Password; //just access
            doc.Entries["B"].Notes = "Notes";

            Assert.IsTrue(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(6, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Uuid);
            Assert.IsTrue(DateTime.UtcNow >= doc.LastSaveTime);
            Assert.IsTrue(doc.LastSaveUser.Length > 0);
            Assert.IsTrue(doc.LastSaveHost.Length > 0);
            Assert.AreNotEqual("Password Safe V3.37", doc.LastSaveApplication);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(5, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Title);
            Assert.AreEqual("A123", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].CreationTime);
            Assert.IsTrue((DateTime.UtcNow >= doc.Entries[0].LastAccessTime) && (doc.Entries[0].Records.Contains(PwSafe.RecordType.LastAccessTime)));

            Assert.AreEqual(6, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Title);
            Assert.AreEqual("B123", doc.Entries[1].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime);
            Assert.IsTrue((DateTime.UtcNow >= doc.Entries[1].LastModificationTime) && (doc.Entries[1].Records.Contains(PwSafe.RecordType.LastModificationTime)));
            Assert.AreEqual("Notes", doc.Entries[1].Notes);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save Simple.psafe3 read-only (track access and modify)
    public void Document_Simple_TrackAccessAndModify_Readonly() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
            doc.IsReadOnly = true;

            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Password Safe V3.37", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);
            Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(4, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("A", doc.Entries[0].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("A123", doc.Entries[0].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.AreEqual(4, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[PwSafe.RecordType.Uuid].Uuid);
            Assert.AreEqual("B", doc.Entries[1].Records[PwSafe.RecordType.Title].Text);
            Assert.AreEqual("B123", doc.Entries[1].Records[PwSafe.RecordType.Password].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[PwSafe.RecordType.CreationTime].Time);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save Simple.psafe3 read-only (try modify)
    public void Document_Simple_Readonly_TryModify() {
        Assert.ThrowsException<NotSupportedException>(() => {
            var msSave = new MemoryStream();
            using var doc = PwSafe.Document.Load(GetResourceStream("Simple.psafe3"), "123");
            doc.IsReadOnly = true;
            doc.Uuid = Guid.NewGuid();
        });
    }


    [TestMethod]  // Document: Load/Save SimpleTree.psafe3
    public void Document_SimpleTree() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("SimpleTree.psafe3"), "123")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;
            doc.IsReadOnly = true;

            Assert.AreEqual(7, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Version);
            Assert.AreEqual(new Guid("5f46a9f5-1b9e-f743-8d58-228d8c99b87f"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 01, 02, 07, 41, 25, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(6, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Uuid);
            Assert.IsTrue(string.Equals("X.Y", doc.Entries[0].Group));
            Assert.AreEqual("A", doc.Entries[0].Title);
            Assert.AreEqual("A123", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 08, 36, 47, DateTimeKind.Utc), doc.Entries[0].CreationTime);
            Assert.AreEqual(new DateTime(2016, 01, 02, 07, 41, 25, DateTimeKind.Utc), doc.Entries[0].LastModificationTime);

            Assert.AreEqual(6, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid);
            Assert.IsTrue(string.Equals("Z", doc.Entries[1].Group));
            Assert.AreEqual("B", doc.Entries[1].Title);
            Assert.AreEqual("B123", doc.Entries[1].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime);
            Assert.AreEqual(new DateTime(2016, 01, 02, 07, 40, 06, DateTimeKind.Utc), doc.Entries[1].LastModificationTime);

            Assert.IsFalse(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(7, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Version);
            Assert.AreEqual(new Guid("5f46a9f5-1b9e-f743-8d58-228d8c99b87f"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 01, 02, 07, 41, 25, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.RecentlyUsedEntries].Text);

            Assert.AreEqual(2, doc.Entries.Count);

            Assert.AreEqual(6, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Uuid);
            Assert.IsTrue(string.Equals("X.Y", doc.Entries[0].Group));
            Assert.AreEqual("A", doc.Entries[0].Title);
            Assert.AreEqual("A123", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 08, 36, 47, DateTimeKind.Utc), doc.Entries[0].CreationTime);
            Assert.AreEqual(new DateTime(2016, 01, 02, 07, 41, 25, DateTimeKind.Utc), doc.Entries[0].LastModificationTime);

            Assert.AreEqual(6, doc.Entries[1].Records.Count);
            Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid);
            Assert.IsTrue(string.Equals("Z", doc.Entries[1].Group));
            Assert.AreEqual("B", doc.Entries[1].Title);
            Assert.AreEqual("B123", doc.Entries[1].Password);
            Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime);
            Assert.AreEqual(new DateTime(2016, 01, 02, 07, 40, 06, DateTimeKind.Utc), doc.Entries[1].LastModificationTime);

            Assert.IsFalse(doc.HasChanged);
        }
    }


    [TestMethod]  // Document: Load/Save Test10.psafe3
    public void Document_Test10() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Test10.psafe3"), "Test")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("f80256c7-3aef-7447-8d2c-65c54981c2ff"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 39, 31, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);
            Assert.AreEqual("1", doc.Headers[PwSafe.HeaderType.TreeDisplayStatus].Text);

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(6, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("74c96b2d-950a-4643-b202-b7967947f781"), doc.Entries[0].Uuid);
            Assert.AreEqual("1234567890", (string)doc.Entries[0].Group);
            Assert.AreEqual("1234567890", doc.Entries[0].Title);
            Assert.AreEqual("1234567890", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 35, 01, DateTimeKind.Utc), doc.Entries[0].CreationTime);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 39, 10, DateTimeKind.Utc), doc.Entries[0].PasswordModificationTime);

            Assert.IsFalse(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "Test")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("f80256c7-3aef-7447-8d2c-65c54981c2ff"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 39, 31, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);
            Assert.AreEqual("1", doc.Headers[PwSafe.HeaderType.TreeDisplayStatus].Text);

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(6, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("74c96b2d-950a-4643-b202-b7967947f781"), doc.Entries[0].Uuid);
            Assert.AreEqual("1234567890", (string)doc.Entries[0].Group);
            Assert.AreEqual("1234567890", doc.Entries[0].Title);
            Assert.AreEqual("1234567890", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 35, 01, DateTimeKind.Utc), doc.Entries[0].CreationTime);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 39, 10, DateTimeKind.Utc), doc.Entries[0].PasswordModificationTime);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save Test11.psafe3
    public void Document_Test11() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Test11.psafe3"), "Test")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(7, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("f80256c7-3aef-7447-8d2c-65c54981c2ff"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 35, 01, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(5, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("74c96b2d-950a-4643-b202-b7967947f781"), doc.Entries[0].Uuid);
            Assert.AreEqual("12345678901", (string)doc.Entries[0].Group);
            Assert.AreEqual("12345678901", doc.Entries[0].Title);
            Assert.AreEqual("12345678901", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 35, 01, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsFalse(doc.HasChanged);
            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "Test")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(7, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("f80256c7-3aef-7447-8d2c-65c54981c2ff"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 35, 01, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(5, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("74c96b2d-950a-4643-b202-b7967947f781"), doc.Entries[0].Uuid);
            Assert.AreEqual("12345678901", (string)doc.Entries[0].Group);
            Assert.AreEqual("12345678901", doc.Entries[0].Title);
            Assert.AreEqual("12345678901", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 01, 11, 07, 35, 01, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save PasswordHistory.psafe3 (history enabled)
    public void Document_TestPasswordHistoryEnabled() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("257a6fba-9816-2a43-9aa7-9bbea870e713"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 47, 40, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.38", doc.LastSaveApplication);

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("3", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("1", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

            Assert.IsFalse(doc.HasChanged);

            doc.Entries[0].Password = "4";
            Assert.IsTrue(doc.HasChanged);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("4", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 44, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("3", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("4", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 44, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("3", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save PasswordHistory.psafe3 (history enabled, more entries)
    public void Document_TestPasswordHistoryEnabledMore() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("257a6fba-9816-2a43-9aa7-9bbea870e713"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 47, 40, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.38", doc.LastSaveApplication);

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("3", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("1", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

            Assert.IsFalse(doc.HasChanged);

            doc.Entries[0].PasswordHistory.MaximumCount = 3;
            doc.Entries[0].Password = "4";
            Assert.IsTrue(doc.HasChanged);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("4", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(3, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(3, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("1", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[1].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 44, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[2].TimeFirstUsed);
            Assert.AreEqual("3", doc.Entries[0].PasswordHistory[2].HistoricalPassword);

            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("4", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(3, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(3, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("1", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[1].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 44, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[2].TimeFirstUsed);
            Assert.AreEqual("3", doc.Entries[0].PasswordHistory[2].HistoricalPassword);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save PasswordHistory.psafe3 (history enabled, indirect change)
    public void Document_TestPasswordHistoryIndirectChange() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("257a6fba-9816-2a43-9aa7-9bbea870e713"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 47, 40, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.38", doc.LastSaveApplication);

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("3", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("1", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

            Assert.IsFalse(doc.HasChanged);

            doc.Entries[0].PasswordHistory.MaximumCount = 3;
            doc.Entries[0][PwSafe.RecordType.Password].Text = "4";
            Assert.IsTrue(doc.HasChanged);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("4", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(3, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(3, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("1", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[1].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 44, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[2].TimeFirstUsed);
            Assert.AreEqual("3", doc.Entries[0].PasswordHistory[2].HistoricalPassword);

            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("4", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(3, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(3, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("1", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[1].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 44, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[2].TimeFirstUsed);
            Assert.AreEqual("3", doc.Entries[0].PasswordHistory[2].HistoricalPassword);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save PasswordHistory.psafe3 (history disabled)
    public void Document_TestPasswordHistoryDisabled() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;
            doc.Entries[0].PasswordHistory.Enabled = false;

            doc.Entries[0].Password = "4";
            Assert.IsTrue(doc.HasChanged);

            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("4", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsFalse(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(0, doc.Entries[0].PasswordHistory.Count);

            Assert.IsFalse(doc.HasChanged);
        }
    }

    [TestMethod]  // Document: Load/Save PasswordHistory.psafe3 (history enabled, clear)
    public void Document_TestPasswordHistoryClear() {
        var msSave = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(8, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("257a6fba-9816-2a43-9aa7-9bbea870e713"), doc.Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 47, 40, DateTimeKind.Utc), doc.LastSaveTime);
            Assert.AreEqual("Josip", doc.LastSaveUser);
            Assert.AreEqual("GANDALF", doc.LastSaveHost);
            Assert.AreEqual("Password Safe V3.38", doc.LastSaveApplication);

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("3", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("1", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

            Assert.IsFalse(doc.HasChanged);

            doc.Entries[0].Password = "4";
            Assert.IsTrue(doc.HasChanged);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("4", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
            Assert.AreEqual("2", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 44, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
            Assert.AreEqual("3", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

            doc.Entries[0].PasswordHistory.Clear();

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(0, doc.Entries[0].PasswordHistory.Count);

            doc.Save(msSave);
            Assert.IsFalse(doc.HasChanged);
        }

        msSave.Position = 0;

        using (var doc = PwSafe.Document.Load(msSave, "123")) { //reload to verify
            doc.TrackAccess = false;
            doc.TrackModify = false;

            Assert.AreEqual(1, doc.Entries.Count);

            Assert.AreEqual(7, doc.Entries[0].Records.Count);
            Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
            Assert.AreEqual("", (string)doc.Entries[0].Group);
            Assert.AreEqual("Test", doc.Entries[0].Title);
            Assert.AreEqual("4", doc.Entries[0].Password);
            Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

            Assert.IsTrue(doc.Entries[0].PasswordHistory.Enabled);
            Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
            Assert.AreEqual(0, doc.Entries[0].PasswordHistory.Count);

            Assert.IsFalse(doc.HasChanged);
        }
    }


    [TestMethod]  // Document: Load/Save new file
    public void Document_NewSaveAndLoad() {
        using var msFile = new MemoryStream();
        using (var doc = new PwSafe.Document("Password")) {
            doc.Entries.Add(new PwSafe.Entry("Test"));
            doc.Save(msFile);
        }

        msFile.Position = 0;

        using (var doc = PwSafe.Document.Load(msFile, "Password")) {
            Assert.AreEqual(1, doc.Entries.Count);
            Assert.AreEqual("Test", doc.Entries[0].Title);
        }
    }


    [TestMethod]  // Document: Change password
    public void Document_ChangePassword() {
        using var msFile = new MemoryStream();
        using (var doc = new PwSafe.Document("Password")) {
            doc.Entries.Add(new PwSafe.Entry("Test"));
            doc.Save(msFile);
            Assert.IsFalse(doc.HasChanged);

            msFile.SetLength(0); //clean previous save

            Assert.AreEqual("50-61-73-73-77-6F-72-64", BitConverter.ToString(doc.GetPassphrase()));

            doc.ChangePassphrase("Password2");
            Assert.IsTrue(doc.HasChanged);

            Assert.AreEqual("50-61-73-73-77-6F-72-64-32", BitConverter.ToString(doc.GetPassphrase()));

            doc.Save(msFile);
            Assert.IsFalse(doc.HasChanged);

            Assert.AreEqual("50-61-73-73-77-6F-72-64-32", BitConverter.ToString(doc.GetPassphrase()));
        }

        msFile.Position = 0;

        using (var doc = PwSafe.Document.Load(msFile, "Password2")) {
            Assert.AreEqual("50-61-73-73-77-6F-72-64-32", BitConverter.ToString(doc.GetPassphrase()));
            Assert.AreEqual(1, doc.Entries.Count);
            Assert.AreEqual("Test", doc.Entries[0].Title);
        }
    }


    [TestMethod]  // Document: Change password (verify old)
    public void Document_ChangeOldPassword() {
        using var msFile = new MemoryStream();
        using (var doc = new PwSafe.Document("Password")) {
            doc.Entries.Add(new PwSafe.Entry("Test"));
            doc.Save(msFile);
            Assert.IsFalse(doc.HasChanged);

            Assert.AreEqual("50-61-73-73-77-6F-72-64", BitConverter.ToString(doc.GetPassphrase()));

            var result = doc.TryChangePassphrase("Password", "Password2");
            Assert.IsTrue(result);
            Assert.IsTrue(doc.HasChanged);

            Assert.AreEqual("50-61-73-73-77-6F-72-64-32", BitConverter.ToString(doc.GetPassphrase()));

            msFile.SetLength(0); //clean previous save
            doc.Save(msFile);
            Assert.IsFalse(doc.HasChanged);

            Assert.AreEqual("50-61-73-73-77-6F-72-64-32", BitConverter.ToString(doc.GetPassphrase()));
        }

        msFile.Position = 0;

        using (var doc = PwSafe.Document.Load(msFile, "Password2")) {
            Assert.AreEqual("50-61-73-73-77-6F-72-64-32", BitConverter.ToString(doc.GetPassphrase()));
            Assert.AreEqual(1, doc.Entries.Count);
            Assert.AreEqual("Test", doc.Entries[0].Title);
        }
    }

    [TestMethod]  // Document: Change password (verify failed)
    public void Document_ChangeOldPasswordFailed() {
        using var msFile = new MemoryStream();
        using (var doc = new PwSafe.Document("Password")) {
            doc.Entries.Add(new PwSafe.Entry("Test"));
            doc.Save(msFile);
            Assert.IsFalse(doc.HasChanged);

            Assert.AreEqual("50-61-73-73-77-6F-72-64", BitConverter.ToString(doc.GetPassphrase()));

            var result = doc.TryChangePassphrase("Password1", "Password2");
            Assert.IsFalse(result);
            Assert.IsFalse(doc.HasChanged);

            Assert.AreEqual("50-61-73-73-77-6F-72-64", BitConverter.ToString(doc.GetPassphrase()));

            msFile.SetLength(0); //clean previous save
            doc.Save(msFile);
            Assert.IsFalse(doc.HasChanged);

            Assert.AreEqual("50-61-73-73-77-6F-72-64", BitConverter.ToString(doc.GetPassphrase()));
        }

        msFile.Position = 0;

        using (var doc = PwSafe.Document.Load(msFile, "Password")) {
            Assert.AreEqual("50-61-73-73-77-6F-72-64", BitConverter.ToString(doc.GetPassphrase()));
            Assert.AreEqual(1, doc.Entries.Count);
            Assert.AreEqual("Test", doc.Entries[0].Title);
        }
    }


    [TestMethod]  // Document: Validate password
    public void Document_ValidatePassword() {
        using var msFile = new MemoryStream();
        using var doc = new PwSafe.Document("Password");
        doc.Entries.Add(new PwSafe.Entry("Test"));
        doc.Save(msFile);
        Assert.IsFalse(doc.HasChanged);

        var result1 = doc.ValidatePassphrase("Password2");
        Assert.IsFalse(result1);
        Assert.IsFalse(doc.HasChanged);

        var result2 = doc.ValidatePassphrase("Password");
        Assert.IsTrue(result2);
        Assert.IsFalse(doc.HasChanged);
    }


    [TestMethod]  // Document: Load Empty.psafe3 (via file name)
    public void Document_Empty_FileName_Load() {
        var fileName = Path.GetTempFileName();
        try {

            using (var streamIn = GetResourceStream("Empty.psafe3"))
            using (var streamOut = new FileStream(fileName, FileMode.Create, FileAccess.Write)) {
                var buffer = new byte[streamIn.Length];
                streamIn.Read(buffer, 0, buffer.Length);
                streamOut.Write(buffer, 0, buffer.Length);
            }

            using var doc = PwSafe.Document.Load(fileName, "123");
            Assert.AreEqual(7, doc.Headers.Count);
            Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
            Assert.AreEqual(new Guid("3b872b47-dee9-4c4f-ba63-4d93a86dfa4c"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
            Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
            Assert.AreEqual(new DateTime(2015, 12, 28, 5, 57, 23, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
            Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
            Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
            Assert.AreEqual("Password Safe V3.37", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);

            Assert.AreEqual(0, doc.Entries.Count);

        } finally {
            File.Delete(fileName);
        }
    }

    [TestMethod]  // Document: Save Empty.psafe3 (via file name)
    public void Document_Empty_FileName_Save() {
        var fileName = Path.GetTempFileName();
        try {

            using (var doc = PwSafe.Document.Load(GetResourceStream("Empty.psafe3"), "123")) {
                doc.IsReadOnly = true;
                doc.Save(fileName);
            }

            using (var doc = PwSafe.Document.Load(fileName, "123")) {
                Assert.AreEqual(7, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[PwSafe.HeaderType.Version].Version);
                Assert.AreEqual(new Guid("3b872b47-dee9-4c4f-ba63-4d93a86dfa4c"), doc.Headers[PwSafe.HeaderType.Uuid].Uuid);
                Assert.AreEqual("", doc.Headers[PwSafe.HeaderType.NonDefaultPreferences].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 5, 57, 23, DateTimeKind.Utc), doc.Headers[PwSafe.HeaderType.TimestampOfLastSave].Time);
                Assert.AreEqual("Josip", doc.Headers[PwSafe.HeaderType.LastSavedByUser].Text);
                Assert.AreEqual("GANDALF", doc.Headers[PwSafe.HeaderType.LastSavedOnHost].Text);
                Assert.AreEqual("Password Safe V3.37", doc.Headers[PwSafe.HeaderType.WhatPerformedLastSave].Text);

                Assert.AreEqual(0, doc.Entries.Count);
            }

        } finally {
            File.Delete(fileName);
        }
    }


    [TestMethod]  // Document: Change to same (track modify)
    public void Document_NoModify_ChangeToSame() {
        using var doc = PwSafe.Document.Load(GetResourceStream("Simple.psafe3"), "123");
        doc.TrackAccess = false;
        Assert.IsFalse(doc.HasChanged);

        doc.Entries[0].Title = "A";
        doc.Entries[1].Title = "B";
        doc.Entries[0].Password = "A123";
        doc.Entries[1].Password = "B123";
        Assert.IsFalse(doc.HasChanged);

        doc.Entries[0].Title = "a";
        Assert.IsTrue(doc.HasChanged);
    }


    [TestMethod]  // Document: Load/Save Policies.psafe3
    public void Document_Policies() {
        using var msFile = new MemoryStream();
        using (var doc = PwSafe.Document.Load(GetResourceStream("Policies.psafe3"), "123")) {
            Assert.IsFalse(doc.HasChanged);

            Assert.AreEqual(3, doc.NamedPasswordPolicies.Count);

            var policy1 = doc.NamedPasswordPolicies[0];
            Assert.AreEqual("Even", policy1.Name);
            Assert.AreEqual((int)(PwSafe.PasswordPolicyStyle.UseUppercase | PwSafe.PasswordPolicyStyle.UseSymbols | PwSafe.PasswordPolicyStyle.MakePronounceable), (int)policy1.Style);
            Assert.AreEqual(12, policy1.TotalPasswordLength);
            Assert.AreEqual(0, policy1.MinimumLowercaseCount);
            Assert.AreEqual(0, policy1.MinimumUppercaseCount);
            Assert.AreEqual(1, policy1.MinimumDigitCount);
            Assert.AreEqual(3, policy1.MinimumSymbolCount);
            Assert.AreEqual("!#$&(+@|", new string(policy1.GetSpecialSymbolSet()));

            var policy2 = doc.NamedPasswordPolicies[1];
            Assert.AreEqual("Hex", policy2.Name);
            Assert.AreEqual((int)(PwSafe.PasswordPolicyStyle.UseHexDigits), (int)policy2.Style);
            Assert.AreEqual(10, policy2.TotalPasswordLength);
            Assert.AreEqual(0, policy2.MinimumLowercaseCount);
            Assert.AreEqual(0, policy2.MinimumUppercaseCount);
            Assert.AreEqual(0, policy2.MinimumDigitCount);
            Assert.AreEqual(0, policy2.MinimumSymbolCount);
            Assert.AreEqual("!#$%&()*+,-./:;<=>?@[\\]^_{|}~", new string(policy2.GetSpecialSymbolSet()));

            var policy3 = doc.NamedPasswordPolicies[2];
            Assert.AreEqual("Odd", policy3.Name);
            Assert.AreEqual((int)(PwSafe.PasswordPolicyStyle.UseLowercase | PwSafe.PasswordPolicyStyle.UseDigits | PwSafe.PasswordPolicyStyle.UseEasyVision), (int)policy3.Style);
            Assert.AreEqual(11, policy3.TotalPasswordLength);
            Assert.AreEqual(2, policy3.MinimumLowercaseCount);
            Assert.AreEqual(4, policy3.MinimumUppercaseCount);
            Assert.AreEqual(1, policy3.MinimumDigitCount);
            Assert.AreEqual(3, policy3.MinimumSymbolCount);
            Assert.AreEqual("!#$%&()*+,-./:;<=>?@[\\]^_{|}~", new string(policy3.GetSpecialSymbolSet()));

            Assert.AreEqual(1, doc.Entries.Count);

            var policy = doc.Entries[0].PasswordPolicy;
            Assert.AreEqual((int)(PwSafe.PasswordPolicyStyle.UseLowercase | PwSafe.PasswordPolicyStyle.UseUppercase | PwSafe.PasswordPolicyStyle.UseDigits | PwSafe.PasswordPolicyStyle.UseSymbols | PwSafe.PasswordPolicyStyle.UseEasyVision), (int)policy.Style);
            Assert.AreEqual(80, policy.TotalPasswordLength);
            Assert.AreEqual(7, policy.MinimumLowercaseCount);
            Assert.AreEqual(5, policy.MinimumUppercaseCount);
            Assert.AreEqual(8, policy.MinimumDigitCount);
            Assert.AreEqual(6, policy.MinimumSymbolCount);
            Assert.AreEqual(@"#$%&*+-/<=>?@\^_~", new string(policy.GetSpecialSymbolSet()));

            doc.Save(msFile);
        }

        msFile.Position = 0;

        using (var doc = PwSafe.Document.Load(msFile, "123")) {
            Assert.IsFalse(doc.HasChanged);

            Assert.AreEqual(3, doc.NamedPasswordPolicies.Count);

            var policy1 = doc.NamedPasswordPolicies[0];
            Assert.AreEqual("Even", policy1.Name);
            Assert.AreEqual((int)(PwSafe.PasswordPolicyStyle.UseUppercase | PwSafe.PasswordPolicyStyle.UseSymbols | PwSafe.PasswordPolicyStyle.MakePronounceable), (int)policy1.Style);
            Assert.AreEqual(12, policy1.TotalPasswordLength);
            Assert.AreEqual(0, policy1.MinimumLowercaseCount);
            Assert.AreEqual(0, policy1.MinimumUppercaseCount);
            Assert.AreEqual(1, policy1.MinimumDigitCount);
            Assert.AreEqual(3, policy1.MinimumSymbolCount);
            Assert.AreEqual("!#$&(+@|", new string(policy1.GetSpecialSymbolSet()));

            var policy2 = doc.NamedPasswordPolicies[1];
            Assert.AreEqual("Hex", policy2.Name);
            Assert.AreEqual((int)(PwSafe.PasswordPolicyStyle.UseHexDigits), (int)policy2.Style);
            Assert.AreEqual(10, policy2.TotalPasswordLength);
            Assert.AreEqual(0, policy2.MinimumLowercaseCount);
            Assert.AreEqual(0, policy2.MinimumUppercaseCount);
            Assert.AreEqual(0, policy2.MinimumDigitCount);
            Assert.AreEqual(0, policy2.MinimumSymbolCount);
            Assert.AreEqual("!#$%&()*+,-./:;<=>?@[\\]^_{|}~", new string(policy2.GetSpecialSymbolSet()));

            var policy3 = doc.NamedPasswordPolicies[2];
            Assert.AreEqual("Odd", policy3.Name);
            Assert.AreEqual((int)(PwSafe.PasswordPolicyStyle.UseLowercase | PwSafe.PasswordPolicyStyle.UseDigits | PwSafe.PasswordPolicyStyle.UseEasyVision), (int)policy3.Style);
            Assert.AreEqual(11, policy3.TotalPasswordLength);
            Assert.AreEqual(2, policy3.MinimumLowercaseCount);
            Assert.AreEqual(4, policy3.MinimumUppercaseCount);
            Assert.AreEqual(1, policy3.MinimumDigitCount);
            Assert.AreEqual(3, policy3.MinimumSymbolCount);
            Assert.AreEqual("!#$%&()*+,-./:;<=>?@[\\]^_{|}~", new string(policy3.GetSpecialSymbolSet()));

            Assert.AreEqual(1, doc.Entries.Count);

            var policy = doc.Entries[0].PasswordPolicy;
            Assert.AreEqual((int)(PwSafe.PasswordPolicyStyle.UseLowercase | PwSafe.PasswordPolicyStyle.UseUppercase | PwSafe.PasswordPolicyStyle.UseDigits | PwSafe.PasswordPolicyStyle.UseSymbols | PwSafe.PasswordPolicyStyle.UseEasyVision), (int)policy.Style);
            Assert.AreEqual(80, policy.TotalPasswordLength);
            Assert.AreEqual(7, policy.MinimumLowercaseCount);
            Assert.AreEqual(5, policy.MinimumUppercaseCount);
            Assert.AreEqual(8, policy.MinimumDigitCount);
            Assert.AreEqual(6, policy.MinimumSymbolCount);
            Assert.AreEqual(@"#$%&*+-/<=>?@\^_~", new string(policy.GetSpecialSymbolSet()));
        }
    }


    [TestMethod]  // Document: Single named policy
    public void Document_NamedPolicies_Single() {
        using var msFile = new MemoryStream();
        using (var doc = new PwSafe.Document("123")) {
            doc.Headers[PwSafe.HeaderType.NamedPasswordPolicies].Text = "0104Test020000a00100200300400";
            doc.Save(msFile);
        }

        msFile.Position = 0;

        using (var doc = PwSafe.Document.Load(msFile, "123")) {
            Assert.AreEqual(1, doc.NamedPasswordPolicies.Count);
            var policy = doc.NamedPasswordPolicies[0];
            Assert.AreEqual("Test", policy.Name);
            Assert.AreEqual(0x0200, (int)policy.Style);
            Assert.AreEqual(10, policy.TotalPasswordLength);
            Assert.AreEqual(1, policy.MinimumLowercaseCount);
            Assert.AreEqual(2, policy.MinimumUppercaseCount);
            Assert.AreEqual(3, policy.MinimumDigitCount);
            Assert.AreEqual(4, policy.MinimumSymbolCount);
            Assert.AreEqual("", new string(policy.GetSpecialSymbolSet()));
        }
    }

    [TestMethod]
    public void Document_NamedPolicies_Single_TooShort() {
        using var msFile = new MemoryStream();
        using (var doc = new PwSafe.Document("123")) {
            doc.Headers[PwSafe.HeaderType.NamedPasswordPolicies].Text = "0104Test020000a0010020030040";
            doc.Save(msFile);
        }

        msFile.Position = 0;

        using (var doc = PwSafe.Document.Load(msFile, "123")) {
            Assert.AreEqual(0, doc.NamedPasswordPolicies.Count);
        }
    }

    [TestMethod]
    public void Document_NamedPolicies_Single_TooLong() {
        using var msFile = new MemoryStream();
        using (var doc = new PwSafe.Document("123")) {
            doc.Headers[PwSafe.HeaderType.NamedPasswordPolicies].Text = "0104Test020000a00100200300400+";
            doc.Save(msFile);
        }

        msFile.Position = 0;

        using (var doc = PwSafe.Document.Load(msFile, "123")) {
            Assert.AreEqual(1, doc.NamedPasswordPolicies.Count);
            var policy = doc.NamedPasswordPolicies[0];
            Assert.AreEqual("Test", policy.Name);
            Assert.AreEqual(0x0200, (int)policy.Style);
            Assert.AreEqual(10, policy.TotalPasswordLength);
            Assert.AreEqual(1, policy.MinimumLowercaseCount);
            Assert.AreEqual(2, policy.MinimumUppercaseCount);
            Assert.AreEqual(3, policy.MinimumDigitCount);
            Assert.AreEqual(4, policy.MinimumSymbolCount);
            Assert.AreEqual("", new string(policy.GetSpecialSymbolSet()));
        }
    }

}
