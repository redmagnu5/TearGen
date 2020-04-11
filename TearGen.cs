using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;

class PrivatePublicKeyGenerator {

    private static void Generate()
    {
      //encrypt s with rsa and send via post to CC
      var csp = new RSACryptoServiceProvider(2048);

      //pub key
      var pubKey = csp.ExportParameters(false);

      //priv Key
      var privKey = csp.ExportParameters(true);

      string pubKeyString;
      {
         var sw = new System.IO.StringWriter();
         var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
         xs.Serialize(sw, pubKey);
         pubKeyString = sw.ToString();
      }

      string privKeyString;
      {
         var sw = new System.IO.StringWriter();
         var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
         xs.Serialize(sw, privKey);
         privKeyString = sw.ToString();
      }

      File.WriteAllText("./pubkey.txt", pubKeyString);
      File.WriteAllText("./privkey.txt", privKeyString);
    }

    private static string Decrypt(string inputText)
    {
      var csp = new RSACryptoServiceProvider(2048);
      var key = File.ReadAllText("./privkey.txt");

      var sr = new System.IO.StringReader(key);
      var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
      var privKey = (RSAParameters)xs.Deserialize(sr);
      var bytesTxt = Convert.FromBase64String(inputText);
      csp.ImportParameters(privKey);
      var decryptedStringBytes = csp.Decrypt(bytesTxt, false);

      var txt = Encoding.Unicode.GetString(decryptedStringBytes);

      return txt;

    }


    static void Main(string[] args)
    {
      Console.WriteLine("Options:");
      Console.WriteLine("1. Generate new key pair");
      Console.WriteLine("2. Decrypt string");
      Console.WriteLine("3. Exit");

      var s = Console.ReadLine();

      if (s == "3")
      {
        Environment.Exit(0);
      }

      if (s == "1")
      {
        Generate();
        Console.WriteLine("Keys generated!");
        Console.ReadLine();
      }

      if (s == "2")
      {
        Console.WriteLine("Paste encrypted string: ");
        var a = Console.ReadLine();
        var b = Decrypt(a);
        Console.WriteLine("Decrypted string is " + b);
        Console.ReadLine();
      }

      else
      {
        Console.WriteLine("Invalid option");
        Console.ReadLine();
      }
    }
}
