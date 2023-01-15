using System.IO;
using System.Reflection;

namespace Tests;

internal static class Helpers {

    public static MemoryStream GetResourceStream(string fileName) {
        var resStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Tests.Resources." + fileName);
        var buffer = new byte[(int)resStream.Length];
        resStream.Read(buffer, 0, buffer.Length);
        return new MemoryStream(buffer) { Position = 0 };
    }

}

