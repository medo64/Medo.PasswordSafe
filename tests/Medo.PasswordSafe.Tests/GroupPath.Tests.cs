using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafe = Medo.Security.Cryptography.PasswordSafe;

namespace Tests;

[TestClass]
public class GroupPath_Tests {

    [TestMethod]  // GroupPath: New
    public void GroupPath_New() {
        PwSafe.GroupPath path = "A";
        Assert.AreEqual("A", path.ToString());
        var segments = path.GetSegments();
        Assert.AreEqual(1, segments.Length);
        Assert.AreEqual("A", segments[0]);
    }

    [TestMethod]  // GroupPath: New (via components)
    public void GroupPath_NewViaComponents() {
        var path = new PwSafe.GroupPath("A", "B");
        Assert.AreEqual("A.B", path.ToString());
        var segments = path.GetSegments();
        Assert.AreEqual(2, segments.Length);
        Assert.AreEqual("A", segments[0]);
        Assert.AreEqual("B", segments[1]);
    }

    [TestMethod]  // GroupPath: New (via escaped components)
    public void GroupPath_NewViaComponentsEscaped() {
        var path = new PwSafe.GroupPath("A", "B.com");
        Assert.AreEqual(@"A.B\.com", path.ToString());

        var segments = path.GetSegments();
        Assert.AreEqual(2, segments.Length);
        Assert.AreEqual("A", segments[0]);
        Assert.AreEqual("B.com", segments[1]);
    }

    [TestMethod]  // GroupPath: New (via escaped components 1)
    public void GroupPath_NewViaComponentsEscaped2() {
        var path = new PwSafe.GroupPath("A", @"B\.com");
        Assert.AreEqual(@"A.B\\.com", path.ToString());

        var segments = path.GetSegments();
        Assert.AreEqual(2, segments.Length);
        Assert.AreEqual("A", segments[0]);
        Assert.AreEqual(@"B\.com", segments[1]);
    }

    [TestMethod]  // GroupPath: New (null)
    public void GroupPath_NewNull() {
        PwSafe.GroupPath path = default(string);
        Assert.AreEqual("", path.ToString());

        var segments = path.GetSegments();
        Assert.AreEqual(1, segments.Length);
        Assert.AreEqual("", segments[0]);
    }

    [TestMethod]  // GroupPath: New tree
    public void GroupPath_NewTree() {
        PwSafe.GroupPath path = "A.B";
        Assert.AreEqual("A.B", path.ToString());

        var segments = path.GetSegments();
        Assert.AreEqual(2, segments.Length);
        Assert.AreEqual("A", segments[0]);
        Assert.AreEqual("B", segments[1]);
    }


    [TestMethod]  // GroupPath: Up
    public void GroupPath_Up() {
        PwSafe.GroupPath path = @"A.B.C\.d";

        Assert.AreEqual(@"A.B.C\.d", path.ToString());
        Assert.AreEqual("A.B", path.Up().ToString());
        Assert.AreEqual("A", path.Up().Up().ToString());
        Assert.AreEqual("", path.Up().Up().Up().ToString());
        Assert.AreEqual("", path.Up().Up().Up().Up().ToString());
    }

    [TestMethod]  // GroupPath: Append
    public void GroupPath_Append() {
        PwSafe.GroupPath path = "";

        Assert.AreEqual("", path.ToString());
        Assert.AreEqual("", path.Append(null).ToString());
        Assert.AreEqual("", path.Append("").ToString());
        Assert.AreEqual("A", path.Append("A").ToString());
        Assert.AreEqual("A.B", path.Append("A").Append("B").ToString());
        Assert.AreEqual(@"A.B.C\.d", path.Append("A").Append("B").Append("C.d").ToString());
        Assert.AreEqual(@"A.B.C\.d", path.Append("A").Append("B").Append("").Append("C.d").Append("").ToString()); //Empty elements are not appended.
    }


    [TestMethod]  // GroupPath: Indexer Get
    public void GroupPath_Indexed() {
        PwSafe.GroupPath path = @"A.B.C\.d";

        Assert.IsNull(path[-1]);
        Assert.AreEqual("A", path[0]);
        Assert.AreEqual("B", path[1]);
        Assert.AreEqual("C.d", path[2]);
        Assert.IsNull(path[3]);
    }

}
