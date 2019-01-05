Imports System
Imports System.Collections.Generic

Namespace AngelsGateLite
    ' AngelsGateLite by NIMIX3 (https://github.com/nimix3/AngelsGateLite) \\
    Class Program
        Public Shared Sub Main(args As String())
            Dim Angel As New AngelsGate()

            Angel.setsIV("<AESIV>")
            Angel.setsKey("<AESKEY>")
            Angel.setPublicKey("-----BEGIN PUBLIC KEY-----" & vbCr & vbLf & "<RSA Public Key>" & vbCr & vbLf & "-----END PUBLIC KEY-----")
            Angel.setEndPoint("https://<endpoint>/api/App.php")
            Angel.setRequest("checkUpdate")

            Dim Data = New Dictionary(Of String, Object)()
            Data("version") = "1.0"
            Angel.setData(Data)
            Dim Res = Angel.SendRequest()

            Console.WriteLine(Res("Data").ToString())
            Console.ReadKey()
            Environment.Exit(0)
        End Sub
    End Class
End Namespace