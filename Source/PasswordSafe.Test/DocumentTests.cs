using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Reflection;
using Medo.Security.Cryptography.PasswordSafe;

namespace PasswordSafe.Test {

    [TestClass]
    public class DocumentTests {

        [TestMethod]
        public void Document_Empty() {
            using (var doc = Document.Load(GetResourceStream("Empty.psafe3"), "123")) {
                Assert.AreEqual(7, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("3b872b47-dee9-4c4f-ba63-4d93a86dfa4c"), doc.Headers[HeaderType.Uuid].Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 5, 57, 23, DateTimeKind.Utc), doc.Headers[HeaderType.TimestampOfLastSave].Time);
                Assert.AreEqual("Josip", doc.Headers[HeaderType.LastSavedByUser].Text);
                Assert.AreEqual("GANDALF", doc.Headers[HeaderType.LastSavedOnHost].Text);
                Assert.AreEqual("Password Safe V3.37", doc.Headers[HeaderType.WhatPerformedLastSave].Text);

                Assert.AreEqual(0, doc.Entries.Count);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void Document_Empty_PasswordMismatch() {
            using (var doc = Document.Load(GetResourceStream("Empty.psafe3"), "XXX")) {
            }
        }


        [TestMethod]
        public void Document_Simple() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(8, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[HeaderType.Uuid].Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Headers[HeaderType.TimestampOfLastSave].Time);
                Assert.AreEqual("Josip", doc.Headers[HeaderType.LastSavedByUser].Text);
                Assert.AreEqual("GANDALF", doc.Headers[HeaderType.LastSavedOnHost].Text);
                Assert.AreEqual("Password Safe V3.37", doc.Headers[HeaderType.WhatPerformedLastSave].Text);
                Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[HeaderType.RecentlyUsedEntries].Text);

                Assert.AreEqual(2, doc.Entries.Count);

                Assert.AreEqual(4, doc.Entries[0].Records.Count);
                Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[RecordType.Uuid].Uuid);
                Assert.AreEqual("A", doc.Entries[0].Records[RecordType.Title].Text);
                Assert.AreEqual("A123", doc.Entries[0].Records[RecordType.Password].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[RecordType.CreationTime].Time);

                Assert.AreEqual(4, doc.Entries[1].Records.Count);
                Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[RecordType.Uuid].Uuid);
                Assert.AreEqual("B", doc.Entries[1].Records[RecordType.Title].Text);
                Assert.AreEqual("B123", doc.Entries[1].Records[RecordType.Password].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[RecordType.CreationTime].Time);

                Assert.IsFalse(doc.HasChanged);
                doc.Save(msSave);
                Assert.IsFalse(doc.HasChanged);
            }

            msSave.Position = 0;

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(8, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[HeaderType.Uuid].Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Headers[HeaderType.TimestampOfLastSave].Time);
                Assert.AreEqual("Josip", doc.Headers[HeaderType.LastSavedByUser].Text);
                Assert.AreEqual("GANDALF", doc.Headers[HeaderType.LastSavedOnHost].Text);
                Assert.AreEqual("Password Safe V3.37", doc.Headers[HeaderType.WhatPerformedLastSave].Text);
                Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[HeaderType.RecentlyUsedEntries].Text);

                Assert.AreEqual(2, doc.Entries.Count);

                Assert.AreEqual(4, doc.Entries[0].Records.Count);
                Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[RecordType.Uuid].Uuid);
                Assert.AreEqual("A", doc.Entries[0].Records[RecordType.Title].Text);
                Assert.AreEqual("A123", doc.Entries[0].Records[RecordType.Password].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[RecordType.CreationTime].Time);

                Assert.AreEqual(4, doc.Entries[1].Records.Count);
                Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[RecordType.Uuid].Uuid);
                Assert.AreEqual("B", doc.Entries[1].Records[RecordType.Title].Text);
                Assert.AreEqual("B123", doc.Entries[1].Records[RecordType.Password].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[RecordType.CreationTime].Time);

                Assert.IsFalse(doc.HasChanged);
            }
        }

        [TestMethod]
        public void Document_Simple_TrackModify() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
                doc.TrackAccess = false;

                doc.Headers[HeaderType.NonDefaultPreferences] = null;
                doc.Headers[HeaderType.RecentlyUsedEntries] = null;
                var x = doc.Entries[0].Password; //just access
                doc.Entries["B"].Notes = "Notes";

                Assert.IsTrue(doc.HasChanged);
                doc.Save(msSave);
                Assert.IsFalse(doc.HasChanged);
            }

            msSave.Position = 0;

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
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

        [TestMethod]
        public void Document_Simple_TrackAccess() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
                doc.TrackModify = false;

                doc.Headers[HeaderType.NonDefaultPreferences] = null;
                doc.Headers[HeaderType.RecentlyUsedEntries] = null;
                var x = doc.Entries[0].Password; //just access
                doc.Entries["B"].Notes = "Notes";

                Assert.IsTrue(doc.HasChanged);
                doc.Save(msSave);
                Assert.IsFalse(doc.HasChanged);
            }

            msSave.Position = 0;

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
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
                Assert.IsTrue((DateTime.UtcNow >= doc.Entries[0].LastAccessTime) && (doc.Entries[0].Records.Contains(RecordType.LastAccessTime)));

                Assert.AreEqual(5, doc.Entries[1].Records.Count);
                Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid);
                Assert.AreEqual("B", doc.Entries[1].Title);
                Assert.AreEqual("B123", doc.Entries[1].Password);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime);
                Assert.AreEqual("Notes", doc.Entries[1].Notes);

                Assert.IsFalse(doc.HasChanged);
            }
        }

        [TestMethod]
        public void Document_Simple_TrackAccessAndModify() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
                doc.Headers[HeaderType.NonDefaultPreferences] = null;
                doc.Headers[HeaderType.RecentlyUsedEntries] = null;
                var x = doc.Entries[0].Password; //just access
                doc.Entries["B"].Notes = "Notes";

                Assert.IsTrue(doc.HasChanged);
                doc.Save(msSave);
                Assert.IsFalse(doc.HasChanged);
            }

            msSave.Position = 0;

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
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
                Assert.IsTrue((DateTime.UtcNow >= doc.Entries[0].LastAccessTime) && (doc.Entries[0].Records.Contains(RecordType.LastAccessTime)));

                Assert.AreEqual(6, doc.Entries[1].Records.Count);
                Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid);
                Assert.AreEqual("B", doc.Entries[1].Title);
                Assert.AreEqual("B123", doc.Entries[1].Password);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime);
                Assert.IsTrue((DateTime.UtcNow >= doc.Entries[1].LastModificationTime) && (doc.Entries[1].Records.Contains(RecordType.LastModificationTime)));
                Assert.AreEqual("Notes", doc.Entries[1].Notes);

                Assert.IsFalse(doc.HasChanged);
            }
        }

        [TestMethod]
        public void Document_Simple_TrackAccessAndModify_Readonly() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
                doc.IsReadOnly = true;

                doc.Save(msSave);
                Assert.IsFalse(doc.HasChanged);
            }

            msSave.Position = 0;

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(8, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("0b073824-a406-2f4b-87b2-48656a6b5011"), doc.Headers[HeaderType.Uuid].Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Headers[HeaderType.TimestampOfLastSave].Time);
                Assert.AreEqual("Josip", doc.Headers[HeaderType.LastSavedByUser].Text);
                Assert.AreEqual("GANDALF", doc.Headers[HeaderType.LastSavedOnHost].Text);
                Assert.AreEqual("Password Safe V3.37", doc.Headers[HeaderType.WhatPerformedLastSave].Text);
                Assert.AreEqual("01a93b6ef7c5af4a5990bd5c20064cc62e", doc.Headers[HeaderType.RecentlyUsedEntries].Text);

                Assert.AreEqual(2, doc.Entries.Count);

                Assert.AreEqual(4, doc.Entries[0].Records.Count);
                Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Records[RecordType.Uuid].Uuid);
                Assert.AreEqual("A", doc.Entries[0].Records[RecordType.Title].Text);
                Assert.AreEqual("A123", doc.Entries[0].Records[RecordType.Password].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 47, DateTimeKind.Utc), doc.Entries[0].Records[RecordType.CreationTime].Time);

                Assert.AreEqual(4, doc.Entries[1].Records.Count);
                Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Records[RecordType.Uuid].Uuid);
                Assert.AreEqual("B", doc.Entries[1].Records[RecordType.Title].Text);
                Assert.AreEqual("B123", doc.Entries[1].Records[RecordType.Password].Text);
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].Records[RecordType.CreationTime].Time);

                Assert.IsFalse(doc.HasChanged);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void Document_Simple_Readonly_TryModify() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("Simple.psafe3"), "123")) {
                doc.IsReadOnly = true;
                doc.Uuid = Guid.NewGuid();
            }
        }


        [TestMethod]
        public void Document_SimpleTree() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("SimpleTree.psafe3"), "123")) {
                doc.TrackAccess = false;
                doc.TrackModify = false;
                doc.IsReadOnly = true;

                Assert.AreEqual(7, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Version);
                Assert.AreEqual(new Guid("5f46a9f5-1b9e-f743-8d58-228d8c99b87f"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
                Assert.AreEqual(new DateTime(2016, 01, 02, 07, 41, 25, DateTimeKind.Utc), doc.LastSaveTime);
                Assert.AreEqual("Josip", doc.LastSaveUser);
                Assert.AreEqual("GANDALF", doc.LastSaveHost);
                Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);
                Assert.AreEqual("", doc.Headers[HeaderType.RecentlyUsedEntries].Text);

                Assert.AreEqual(2, doc.Entries.Count);

                Assert.AreEqual(6, doc.Entries[0].Records.Count, "[0]");
                Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Uuid, "Uuid[0]");
                Assert.IsTrue(string.Equals("X.Y", doc.Entries[0].Group), "Group[0]");
                Assert.AreEqual("A", doc.Entries[0].Title, "Title[0]");
                Assert.AreEqual("A123", doc.Entries[0].Password, "Password[0]");
                Assert.AreEqual(new DateTime(2015, 12, 28, 08, 36, 47, DateTimeKind.Utc), doc.Entries[0].CreationTime, "CreationTime[0]");
                Assert.AreEqual(new DateTime(2016, 01, 02, 07, 41, 25, DateTimeKind.Utc), doc.Entries[0].LastModificationTime, "LastModificationTime[0]");

                Assert.AreEqual(6, doc.Entries[1].Records.Count, "[1]");
                Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid, "Uuid[1]");
                Assert.IsTrue(string.Equals("Z", doc.Entries[1].Group), "Group[1]");
                Assert.AreEqual("B", doc.Entries[1].Title, "Title[1]");
                Assert.AreEqual("B123", doc.Entries[1].Password, "Password[1]");
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime, "CreationTime[1]");
                Assert.AreEqual(new DateTime(2016, 01, 02, 07, 40, 06, DateTimeKind.Utc), doc.Entries[1].LastModificationTime, "LastModificationTime[1]");

                Assert.IsFalse(doc.HasChanged);
                doc.Save(msSave);
                Assert.IsFalse(doc.HasChanged);
            }

            msSave.Position = 0;

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(7, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Version);
                Assert.AreEqual(new Guid("5f46a9f5-1b9e-f743-8d58-228d8c99b87f"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
                Assert.AreEqual(new DateTime(2016, 01, 02, 07, 41, 25, DateTimeKind.Utc), doc.LastSaveTime);
                Assert.AreEqual("Josip", doc.LastSaveUser);
                Assert.AreEqual("GANDALF", doc.LastSaveHost);
                Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);
                Assert.AreEqual("", doc.Headers[HeaderType.RecentlyUsedEntries].Text);

                Assert.AreEqual(2, doc.Entries.Count);

                Assert.AreEqual(6, doc.Entries[0].Records.Count, "[0]");
                Assert.AreEqual(new Guid("f76e3ba9-afc5-594a-90bd-5c20064cc62e"), doc.Entries[0].Uuid, "Uuid[0]");
                Assert.IsTrue(string.Equals("X.Y", doc.Entries[0].Group), "Group[0]");
                Assert.AreEqual("A", doc.Entries[0].Title, "Title[0]");
                Assert.AreEqual("A123", doc.Entries[0].Password, "Password[0]");
                Assert.AreEqual(new DateTime(2015, 12, 28, 08, 36, 47, DateTimeKind.Utc), doc.Entries[0].CreationTime, "CreationTime[0]");
                Assert.AreEqual(new DateTime(2016, 01, 02, 07, 41, 25, DateTimeKind.Utc), doc.Entries[0].LastModificationTime, "LastModificationTime[0]");

                Assert.AreEqual(6, doc.Entries[1].Records.Count, "[1]");
                Assert.AreEqual(new Guid("fb40f24e-68ec-c74e-8e87-293dd274d10c"), doc.Entries[1].Uuid, "Uuid[1]");
                Assert.IsTrue(string.Equals("Z", doc.Entries[1].Group), "Group[1]");
                Assert.AreEqual("B", doc.Entries[1].Title, "Title[1]");
                Assert.AreEqual("B123", doc.Entries[1].Password, "Password[1]");
                Assert.AreEqual(new DateTime(2015, 12, 28, 8, 36, 59, DateTimeKind.Utc), doc.Entries[1].CreationTime, "CreationTime[1]");
                Assert.AreEqual(new DateTime(2016, 01, 02, 07, 40, 06, DateTimeKind.Utc), doc.Entries[1].LastModificationTime, "LastModificationTime[1]");

                Assert.IsFalse(doc.HasChanged);
            }
        }


        [TestMethod]
        public void Document_Test10() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("Test10.psafe3"), "Test")) {
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(8, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("f80256c7-3aef-7447-8d2c-65c54981c2ff"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
                Assert.AreEqual(new DateTime(2016, 01, 11, 07, 39, 31, DateTimeKind.Utc), doc.LastSaveTime);
                Assert.AreEqual("Josip", doc.LastSaveUser);
                Assert.AreEqual("GANDALF", doc.LastSaveHost);
                Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);
                Assert.AreEqual("1", doc.Headers[HeaderType.TreeDisplayStatus].Text);

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

            using (var doc = Document.Load(msSave, "Test")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(8, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("f80256c7-3aef-7447-8d2c-65c54981c2ff"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
                Assert.AreEqual(new DateTime(2016, 01, 11, 07, 39, 31, DateTimeKind.Utc), doc.LastSaveTime);
                Assert.AreEqual("Josip", doc.LastSaveUser);
                Assert.AreEqual("GANDALF", doc.LastSaveHost);
                Assert.AreEqual("Password Safe V3.37", doc.LastSaveApplication);
                Assert.AreEqual("1", doc.Headers[HeaderType.TreeDisplayStatus].Text);

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

        [TestMethod]
        public void Document_Test11() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("Test11.psafe3"), "Test")) {
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(7, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("f80256c7-3aef-7447-8d2c-65c54981c2ff"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
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

            using (var doc = Document.Load(msSave, "Test")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(7, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("f80256c7-3aef-7447-8d2c-65c54981c2ff"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
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

        [TestMethod]
        public void Document_TestPasswordHistoryEnabled() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(8, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("257a6fba-9816-2a43-9aa7-9bbea870e713"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
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

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
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

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
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

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(1, doc.Entries.Count);

                Assert.AreEqual(7, doc.Entries[0].Records.Count);
                Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
                Assert.AreEqual("", (string)doc.Entries[0].Group);
                Assert.AreEqual("Test", doc.Entries[0].Title);
                Assert.AreEqual("4", doc.Entries[0].Password);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
                Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
                Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
                Assert.AreEqual("2", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 44, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
                Assert.AreEqual("3", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

                Assert.IsFalse(doc.HasChanged);
            }
        }

        [TestMethod]
        public void Document_TestPasswordHistoryEnabledMore() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(8, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("257a6fba-9816-2a43-9aa7-9bbea870e713"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
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

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
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

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
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

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(1, doc.Entries.Count);

                Assert.AreEqual(7, doc.Entries[0].Records.Count);
                Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
                Assert.AreEqual("", (string)doc.Entries[0].Group);
                Assert.AreEqual("Test", doc.Entries[0].Title);
                Assert.AreEqual("4", doc.Entries[0].Password);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
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

        [TestMethod]
        public void Document_TestPasswordHistoryIndirectChange() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(8, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("257a6fba-9816-2a43-9aa7-9bbea870e713"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
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

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
                Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
                Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
                Assert.AreEqual("1", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
                Assert.AreEqual("2", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

                Assert.IsFalse(doc.HasChanged);

                doc.Entries[0].PasswordHistory.MaximumCount = 3;
                doc.Entries[0][RecordType.Password].Text = "4";
                Assert.IsTrue(doc.HasChanged);

                Assert.AreEqual(7, doc.Entries[0].Records.Count);
                Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
                Assert.AreEqual("", (string)doc.Entries[0].Group);
                Assert.AreEqual("Test", doc.Entries[0].Title);
                Assert.AreEqual("4", doc.Entries[0].Password);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
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

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(1, doc.Entries.Count);

                Assert.AreEqual(7, doc.Entries[0].Records.Count);
                Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
                Assert.AreEqual("", (string)doc.Entries[0].Group);
                Assert.AreEqual("Test", doc.Entries[0].Title);
                Assert.AreEqual("4", doc.Entries[0].Password);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
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

        [TestMethod]
        public void Document_TestPasswordHistoryDisabled() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
                doc.TrackAccess = false;
                doc.TrackModify = false;
                doc.Entries[0].PasswordHistory.Enabled = false;

                doc.Entries[0].Password = "4";
                Assert.IsTrue(doc.HasChanged);

                doc.Save(msSave);
                Assert.IsFalse(doc.HasChanged);
            }

            msSave.Position = 0;

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(1, doc.Entries.Count);

                Assert.AreEqual(7, doc.Entries[0].Records.Count);
                Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
                Assert.AreEqual("", (string)doc.Entries[0].Group);
                Assert.AreEqual("Test", doc.Entries[0].Title);
                Assert.AreEqual("4", doc.Entries[0].Password);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

                Assert.AreEqual(false, doc.Entries[0].PasswordHistory.Enabled);
                Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
                Assert.AreEqual(0, doc.Entries[0].PasswordHistory.Count);

                Assert.IsFalse(doc.HasChanged);
            }
        }

        [TestMethod]
        public void Document_TestPasswordHistoryClear() {
            var msSave = new MemoryStream();
            using (var doc = Document.Load(GetResourceStream("PasswordHistory.psafe3"), "123")) {
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(8, doc.Headers.Count);
                Assert.AreEqual(0x030D, doc.Headers[HeaderType.Version].Version);
                Assert.AreEqual(new Guid("257a6fba-9816-2a43-9aa7-9bbea870e713"), doc.Uuid);
                Assert.AreEqual("", doc.Headers[HeaderType.NonDefaultPreferences].Text);
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

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
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

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
                Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
                Assert.AreEqual(2, doc.Entries[0].PasswordHistory.Count);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 27, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[0].TimeFirstUsed);
                Assert.AreEqual("2", doc.Entries[0].PasswordHistory[0].HistoricalPassword);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 44, DateTimeKind.Utc), doc.Entries[0].PasswordHistory[1].TimeFirstUsed);
                Assert.AreEqual("3", doc.Entries[0].PasswordHistory[1].HistoricalPassword);

                doc.Entries[0].PasswordHistory.Clear();

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
                Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
                Assert.AreEqual(0, doc.Entries[0].PasswordHistory.Count);

                doc.Save(msSave);
                Assert.IsFalse(doc.HasChanged);
            }

            msSave.Position = 0;

            using (var doc = Document.Load(msSave, "123")) { //reload to verify
                doc.TrackAccess = false;
                doc.TrackModify = false;

                Assert.AreEqual(1, doc.Entries.Count);

                Assert.AreEqual(7, doc.Entries[0].Records.Count);
                Assert.AreEqual(new Guid("e857fe9c-091e-b44c-8574-e435549e1cc7"), doc.Entries[0].Uuid);
                Assert.AreEqual("", (string)doc.Entries[0].Group);
                Assert.AreEqual("Test", doc.Entries[0].Title);
                Assert.AreEqual("4", doc.Entries[0].Password);
                Assert.AreEqual(new DateTime(2016, 06, 25, 20, 32, 15, DateTimeKind.Utc), doc.Entries[0].CreationTime);

                Assert.AreEqual(true, doc.Entries[0].PasswordHistory.Enabled);
                Assert.AreEqual(2, doc.Entries[0].PasswordHistory.MaximumCount);
                Assert.AreEqual(0, doc.Entries[0].PasswordHistory.Count);

                Assert.IsFalse(doc.HasChanged);
            }
        }


        [TestMethod]
        public void Document_NewSaveAndLoad() {
            using (var msFile = new MemoryStream()) {
                using (var doc = new Document("Password")) {
                    doc.Entries.Add(new Entry("Test"));
                    doc.Save(msFile);
                }

                msFile.Position = 0;

                using (var doc = Document.Load(msFile, "Password")) {
                    Assert.AreEqual(1, doc.Entries.Count);
                    Assert.AreEqual("Test", doc.Entries[0].Title);
                }
            }
        }


        [TestMethod]
        public void Document_ChangePassword() {
            using (var msFile = new MemoryStream()) {
                using (var doc = new Document("Password")) {
                    doc.Entries.Add(new Entry("Test"));
                    doc.Save(msFile);
                    Assert.IsFalse(doc.HasChanged);

                    msFile.SetLength(0); //clean previous save

                    doc.ChangePassphrase("Password2");
                    Assert.IsTrue(doc.HasChanged);

                    doc.Save(msFile);
                    Assert.IsFalse(doc.HasChanged);
                }

                msFile.Position = 0;

                using (var doc = Document.Load(msFile, "Password2")) {
                    Assert.AreEqual(1, doc.Entries.Count);
                    Assert.AreEqual("Test", doc.Entries[0].Title);
                }
            }
        }


        [TestMethod]
        public void Document_ChangeOldPassword() {
            using (var msFile = new MemoryStream()) {
                using (var doc = new Document("Password")) {
                    doc.Entries.Add(new Entry("Test"));
                    doc.Save(msFile);
                    Assert.IsFalse(doc.HasChanged);

                    var result = doc.TryChangePassphrase("Password", "Password2");
                    Assert.IsTrue(result);
                    Assert.IsTrue(doc.HasChanged);

                    msFile.SetLength(0); //clean previous save
                    doc.Save(msFile);
                    Assert.IsFalse(doc.HasChanged);
                }

                msFile.Position = 0;

                using (var doc = Document.Load(msFile, "Password2")) {
                    Assert.AreEqual(1, doc.Entries.Count);
                    Assert.AreEqual("Test", doc.Entries[0].Title);
                }
            }
        }

        [TestMethod]
        public void Document_ChangeOldPasswordFailed() {
            using (var msFile = new MemoryStream()) {
                using (var doc = new Document("Password")) {
                    doc.Entries.Add(new Entry("Test"));
                    doc.Save(msFile);
                    Assert.IsFalse(doc.HasChanged);

                    var result = doc.TryChangePassphrase("Password1", "Password2");
                    Assert.IsFalse(result);
                    Assert.IsFalse(doc.HasChanged);

                    msFile.SetLength(0); //clean previous save
                    doc.Save(msFile);
                    Assert.IsFalse(doc.HasChanged);
                }

                msFile.Position = 0;

                using (var doc = Document.Load(msFile, "Password")) {
                    Assert.AreEqual(1, doc.Entries.Count);
                    Assert.AreEqual("Test", doc.Entries[0].Title);
                }
            }
        }


        [TestMethod]
        public void Document_ValidatePassword() {
            using (var msFile = new MemoryStream()) {
                using (var doc = new Document("Password")) {
                    doc.Entries.Add(new Entry("Test"));
                    doc.Save(msFile);
                    Assert.IsFalse(doc.HasChanged);

                    var result1 = doc.ValidatePassphrase("Password2");
                    Assert.IsFalse(result1);
                    Assert.IsFalse(doc.HasChanged);

                    var result2 = doc.ValidatePassphrase("Password");
                    Assert.IsTrue(result2);
                    Assert.IsFalse(doc.HasChanged);
                }
            }
        }


        #region Utils

        private static MemoryStream GetResourceStream(string fileName) {
            var resStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("PasswordSafe.Test.Resources." + fileName);
            var buffer = new byte[(int)resStream.Length];
            resStream.Read(buffer, 0, buffer.Length);
            return new MemoryStream(buffer) { Position = 0 };
        }

        #endregion

    }

}
