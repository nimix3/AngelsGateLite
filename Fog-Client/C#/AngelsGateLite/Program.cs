using System;
using System.Collections.Generic;

namespace AngelsGateLite
{
    // AngelsGateLite by NIMIX3 (https://github.com/nimix3/AngelsGateLite) \\
    class Program
    {
        static void Main(string[] args)
        {
            AngelsGate Angel = new AngelsGate();

            Angel.setsIV("<AESIV>");
            Angel.setsKey("<AESKEY>");
            Angel.setPublicKey(@"-----BEGIN PUBLIC KEY-----
                <RSA Public Key>
                -----END PUBLIC KEY-----");
            Angel.setEndPoint("https://<endpoint>/api/App.php");
            Angel.setRequest("checkUpdate");

            var Data = new Dictionary<string, object> { };
            Data["version"] = "1.0";
            Angel.setData(Data);
            var Res = Angel.SendRequest();

            Console.WriteLine(Res["Data"].ToString());
            Console.ReadKey();
            Environment.Exit(0);
        }
    }
}
