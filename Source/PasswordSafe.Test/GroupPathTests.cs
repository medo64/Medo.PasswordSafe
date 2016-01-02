using Medo.Security.Cryptography.PasswordSafe;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace PasswordSafe.Test {
    [TestClass]
    public class GroupPathTests {

        [TestMethod]
        public void GroupPath_New() {
            GroupPath path = "A";
            Assert.AreEqual("A", path.ToString());

            var segments = path.GetSegments();
            Assert.AreEqual(1, segments.Length);
            Assert.AreEqual("A", segments[0]);
        }

        [TestMethod]
        public void GroupPath_NewViaComponents() {
            GroupPath path = new GroupPath("A", "B");
            Assert.AreEqual("A.B", path.ToString());

            var segments = path.GetSegments();
            Assert.AreEqual(2, segments.Length);
            Assert.AreEqual("A", segments[0]);
            Assert.AreEqual("B", segments[1]);
        }

        [TestMethod]
        public void GroupPath_NewViaComponentsEscaped() {
            GroupPath path = new GroupPath("A", "B.com");
            Assert.AreEqual(@"A.B\.com", path.ToString());

            var segments = path.GetSegments();
            Assert.AreEqual(2, segments.Length);
            Assert.AreEqual("A", segments[0]);
            Assert.AreEqual("B.com", segments[1]);
        }

        [TestMethod]
        public void GroupPath_NewViaComponentsEscaped2() {
            GroupPath path = new GroupPath("A", @"B\.com");
            Assert.AreEqual(@"A.B\\.com", path.ToString());

            var segments = path.GetSegments();
            Assert.AreEqual(2, segments.Length);
            Assert.AreEqual("A", segments[0]);
            Assert.AreEqual(@"B\.com", segments[1]);
        }

        [TestMethod]
        public void GroupPath_NewNull() {
            GroupPath path = default(string);
            Assert.AreEqual("", path.ToString());

            var segments = path.GetSegments();
            Assert.AreEqual(1, segments.Length);
            Assert.AreEqual("", segments[0]);
        }

        [TestMethod]
        public void GroupPath_NewTree() {
            GroupPath path = "A.B";
            Assert.AreEqual("A.B", path.ToString());

            var segments = path.GetSegments();
            Assert.AreEqual(2, segments.Length);
            Assert.AreEqual("A", segments[0]);
            Assert.AreEqual("B", segments[1]);
        }


        [TestMethod]
        public void GroupPath_Up() {
            GroupPath path = @"A.B.C\.d";

            Assert.AreEqual(@"A.B.C\.d", path.ToString());
            Assert.AreEqual("A.B", path.Up().ToString());
            Assert.AreEqual("A", path.Up().Up().ToString());
            Assert.AreEqual("", path.Up().Up().Up().ToString());
            Assert.AreEqual("", path.Up().Up().Up().Up().ToString());
        }

        [TestMethod]
        public void GroupPath_Append() {
            GroupPath path = "";

            Assert.AreEqual("", path.ToString());
            Assert.AreEqual("", path.Append(null).ToString());
            Assert.AreEqual("", path.Append("").ToString());
            Assert.AreEqual("A", path.Append("A").ToString());
            Assert.AreEqual("A.B", path.Append("A").Append("B").ToString());
            Assert.AreEqual(@"A.B.C\.d", path.Append("A").Append("B").Append("C.d").ToString());
            Assert.AreEqual(@"A.B.C\.d", path.Append("A").Append("B").Append("").Append("C.d").Append("").ToString(), "Empty elements are not appended.");
        }


        [TestMethod]
        public void GroupPath_Indexed() {
            GroupPath path = @"A.B.C\.d";

            Assert.AreEqual(null, path[-1]);
            Assert.AreEqual("A", path[0]);
            Assert.AreEqual("B", path[1]);
            Assert.AreEqual("C.d", path[2]);
            Assert.AreEqual(null, path[3]);
        }

    }
}
