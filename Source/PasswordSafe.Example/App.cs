using PasswordSafe = Medo.Security.Cryptography.PasswordSafe;
using System;
using System.IO;

namespace Example {
    class App {
        static void Main(string[] args) {
            PasswordSafe.Document doc;

            //Load
            using (var inputStream = new FileStream(@"..\Source\PasswordSafe.Test\Resources\Simple.psafe3", FileMode.Open)) {
                doc = PasswordSafe.Document.Load(inputStream, "123");
            }
            Show(doc, ConsoleColor.Gray);

            //modify
            doc.Entries["A"].Title = "Ax";
            doc.Entries["Ax"].Password = "A123x";

            //remove
            doc.Entries["B"] = null;

            //create new
            doc.Entries["C"].UserName = "Cuser";
            doc.Entries["C"].Password = "C123";
            doc.Entries["C"].Group = "Test";
            doc.Entries["C", PasswordSafe.RecordType.Group] = null;

            Show(doc, ConsoleColor.White);

            //save
            using (var outputStream = new FileStream(@"New.psafe3", FileMode.Create)) {
                doc.Save(outputStream);
            }

            using (var inputStream = new FileStream(@"New.psafe3", FileMode.Open)) {
                doc = PasswordSafe.Document.Load(inputStream, "123");
            }
            Show(doc, ConsoleColor.Yellow);

            Console.ReadKey();
        }


        private static void Show(PasswordSafe.Document doc, ConsoleColor color) {
            Console.ForegroundColor = color;

            Console.WriteLine("Headers");
            foreach (var field in doc.Headers) {
                Console.WriteLine("    {0}: {1}", field.HeaderType, field.ToString());
            }
            Console.WriteLine();

            Console.WriteLine("Entries");
            foreach (var entry in doc.Entries) {
                Console.WriteLine("    {0}:", entry.ToString());
                foreach (var field in entry.Records) {
                    Console.WriteLine("        {0}: {1}", field.RecordType, field.ToString());
                }
                Console.WriteLine();
            }

            Console.ResetColor();
        }
    }
}
