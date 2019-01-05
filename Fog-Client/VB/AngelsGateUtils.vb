Imports Org.BouncyCastle.Crypto
Imports Org.BouncyCastle.Crypto.Parameters
Imports Org.BouncyCastle.OpenSsl
Imports Org.BouncyCastle.Security
Imports System
Imports System.Diagnostics
Imports System.IO
Imports System.Linq
Imports System.Security.Cryptography
Imports System.Text
Imports System.Runtime.InteropServices

Namespace AngelsGateLite
    Public Class AngelsGateUtils
        Public Shared _PUB_KEY As String = ""
        <System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError:=True, ExactSpelling:=True)>
        Private Shared Function CheckRemoteDebuggerPresent(ByVal hProcess As IntPtr, ByRef isDebuggerPresent As Boolean) As Boolean

        End Function
        <System.Runtime.InteropServices.DllImport("kernel32.dll")>
        Private Shared Function GetPhysicallyInstalledSystemMemory(<Out> ByRef TotalMemoryInKilobytes As Long) As Boolean

        End Function

        Public Sub setupHPKP(ByVal CertSig As String)
            _PUB_KEY = CertSig
        End Sub

        Public Function GetProcessId() As String
            Try
                Dim retVal As String = GetWMI("Win32_Processor", "UniqueId")

                If retVal Is "" Then
                    retVal = GetWMI("Win32_Processor", "ProcessorId")

                    If retVal Is "" Then
                        retVal = GetWMI("Win32_Processor", "Name")

                        If retVal Is "" Then
                            retVal = GetWMI("Win32_Processor", "Manufacturer")
                        End If

                        retVal &= GetWMI("Win32_Processor", "MaxClockSpeed")
                    End If
                End If

                Return CreateMD5(retVal)
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Public Function GetBiosSerial() As String
            Dim ret As String = Nothing

            Try
                ret = Me.CreateMD5(Me.GetWMI("Win32_BIOS", "Manufacturer") & Me.GetWMI("Win32_BIOS", "SMBIOSBIOSVersion") & Me.GetWMI("Win32_BIOS", "IdentificationCode") & Me.GetWMI("Win32_BIOS", "SerialNumber") & Me.GetWMI("Win32_BIOS", "ReleaseDate") & Me.GetWMI("Win32_BIOS", "Version"))
            Catch
                ret = Nothing
            End Try

            If String.IsNullOrEmpty(ret) Then
                Return Me.GetProcessId()
            Else
                Return ret
            End If
        End Function

        Public Function GetUUID() As String
            Dim searcher As System.Management.ManagementObjectSearcher = New System.Management.ManagementObjectSearcher("root\CIMV2", "SELECT * FROM Win32_ComputerSystemProduct")

            For Each wmi As System.Management.ManagementObject In searcher.[Get]()

                Try
                    Return wmi.GetPropertyValue("UUID").ToString()
                Catch ex As Exception
                    Return Nothing
                End Try
            Next

            Return Nothing
        End Function

        Public Function GetMACAddress() As String
            Dim ret As String = Nothing

            Try
                ret = Me.CreateMD5(GetWMI("Win32_NetworkAdapterConfiguration", "MACAddress", "IPEnabled"))
            Catch
                ret = Nothing
            End Try

            If String.IsNullOrEmpty(ret) Then
                Return Me.GetProcessId()
            Else
                Return ret
            End If
        End Function

        Public Function GetHDDSerial() As String
            Dim ret As String = Nothing

            Try
                ret = Me.CreateMD5(Me.GetWMI("Win32_DiskDrive", "Model") & Me.GetWMI("Win32_DiskDrive", "Manufacturer") & Me.GetWMI("Win32_DiskDrive", "Signature") & Me.GetWMI("Win32_DiskDrive", "TotalHeads"))
            Catch
                ret = Nothing
            End Try

            If String.IsNullOrEmpty(ret) Then
                Return Me.GetProcessId()
            Else
                Return ret
            End If
        End Function

        Public Function GetBoardMaker() As String
            Dim ret As String = Nothing

            Try
                ret = Me.CreateMD5(Me.GetWMI("Win32_BaseBoard", "Model") & Me.GetWMI("Win32_BaseBoard", "Manufacturer") & Me.GetWMI("Win32_BaseBoard", "Name") & Me.GetWMI("Win32_BaseBoard", "SerialNumber"))
            Catch
                ret = Nothing
            End Try

            If String.IsNullOrEmpty(ret) Then
                Return Me.GetProcessId()
            Else
                Return ret
            End If
        End Function

        Public Function DetectVM() As Boolean
            Try

                Using searcher = New System.Management.ManagementObjectSearcher("Select * from Win32_ComputerSystem")

                    Using items = searcher.[Get]()

                        For Each item In items
                            Dim manufacturer As String = item("Manufacturer").ToString().ToLower()

                            If (manufacturer Is "microsoft corporation" AndAlso item("Model").ToString().ToUpperInvariant().Contains("VIRTUAL")) OrElse manufacturer.Contains("vmware") OrElse item("Model").ToString() Is "VirtualBox" Then
                                Return True
                            End If
                        Next
                    End Using
                End Using

                Return False
            Catch ex As Exception
                Return True
            End Try
        End Function

        Public Function GetOSSerial() As String
            Try
                Dim os As System.Management.ManagementObject = New System.Management.ManagementObject("Win32_OperatingSystem=@")
                Dim serial As String = CStr(os("SerialNumber"))
                Return serial
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Public Function DetectDBG() As Boolean
            Try
                Dim re As System.Diagnostics.Process() = System.Diagnostics.Process.GetProcessesByName("Reflector")
                Dim pname As System.Diagnostics.Process() = System.Diagnostics.Process.GetProcessesByName("CFF Explorer")
                Dim OLLYDBG As System.Diagnostics.Process() = System.Diagnostics.Process.GetProcessesByName("Ollydbg")
                Dim ImmunityDebugger As System.Diagnostics.Process() = System.Diagnostics.Process.GetProcessesByName("ImmunityDebugger")
                Dim W32DSM89 As System.Diagnostics.Process() = System.Diagnostics.Process.GetProcessesByName("W32DSM89")
                Dim DeDe As System.Diagnostics.Process() = System.Diagnostics.Process.GetProcessesByName("DeDe")
                Dim ObsidianGUI As System.Diagnostics.Process() = System.Diagnostics.Process.GetProcessesByName("ObsidianGUI")
                Dim exeinfope As System.Diagnostics.Process() = System.Diagnostics.Process.GetProcessesByName("exeinfope")
                Dim AT4RE_FastScanner As System.Diagnostics.Process() = System.Diagnostics.Process.GetProcessesByName("AT4RE_FastScanner")

                If re.Length <> 0 OrElse pname.Length <> 0 OrElse OLLYDBG.Length <> 0 OrElse ImmunityDebugger.Length <> 0 OrElse W32DSM89.Length <> 0 OrElse DeDe.Length <> 0 OrElse exeinfope.Length <> 0 OrElse AT4RE_FastScanner.Length <> 0 OrElse ObsidianGUI.Length <> 0 Then
                    Return True
                End If

                Dim isDebuggerPresent As Boolean = False
                CheckRemoteDebuggerPresent(System.Diagnostics.Process.GetCurrentProcess().Handle, isDebuggerPresent)
                Return isDebuggerPresent
            Catch ex As Exception
                Return True
            End Try
        End Function

        Public Function GetRAMcapacity() As String
            Try
                Dim memKb As Long
                GetPhysicallyInstalledSystemMemory(memKb)
                Return memKb.ToString()
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Public Function GetWindowsID() As String
            Try
                Dim x64Result As String = String.Empty
                Dim x86Result As String = String.Empty
                Dim keyBaseX64 As Microsoft.Win32.RegistryKey = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                Dim keyBaseX86 As Microsoft.Win32.RegistryKey = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32)
                Dim keyX64 As Microsoft.Win32.RegistryKey = keyBaseX64.OpenSubKey("SOFTWARE\Microsoft\Cryptography", Microsoft.Win32.RegistryKeyPermissionCheck.ReadSubTree)
                Dim keyX86 As Microsoft.Win32.RegistryKey = keyBaseX86.OpenSubKey("SOFTWARE\Microsoft\Cryptography", Microsoft.Win32.RegistryKeyPermissionCheck.ReadSubTree)
                Dim resultObjX64 As Object = keyX64.GetValue("MachineGuid", CObj("default"))
                Dim resultObjX86 As Object = keyX86.GetValue("MachineGuid", CObj("default"))
                keyX64.Close()
                keyX86.Close()
                keyBaseX64.Close()
                keyBaseX86.Close()
                keyX64.Dispose()
                keyX86.Dispose()
                keyBaseX64.Dispose()
                keyBaseX86.Dispose()
                keyX64 = Nothing
                keyX86 = Nothing
                keyBaseX64 = Nothing
                keyBaseX86 = Nothing

                If resultObjX64 IsNot Nothing AndAlso resultObjX64.ToString() IsNot "default" Then
                    Return resultObjX64.ToString()
                End If

                If resultObjX86 IsNot Nothing AndAlso resultObjX86.ToString() IsNot "default" Then
                    Return resultObjX86.ToString()
                End If

                Return Nothing
            Catch __unusedException1__ As Exception
                Return Nothing
            End Try
        End Function

        Public Function GetGraphicCard() As String
            Dim ret As String = Nothing

            Try
                ret = Me.CreateMD5(Me.GetWMI("Win32_VideoController", "Name") & Me.GetWMI("Win32_VideoController", "DriverVersion"))
            Catch
                ret = Nothing
            End Try

            If String.IsNullOrEmpty(ret) Then
                Return Me.GetProcessId()
            Else
                Return ret
            End If
        End Function

        Private Shared Function GetWMI(ByVal wmiClass As String, ByVal wmiProperty As String, ByVal wmiMustBeTrue As String) As String
            Try
                Dim result As String = ""
                Dim mc As System.Management.ManagementClass = New System.Management.ManagementClass(wmiClass)
                Dim moc As System.Management.ManagementObjectCollection = mc.GetInstances()

                For Each mo As System.Management.ManagementObject In moc

                    If mo(wmiMustBeTrue).ToString() Is "True" Then

                        If result Is "" Then

                            Try
                                result = mo(wmiProperty).ToString()
                                Exit For
                            Catch
                            End Try
                        End If
                    End If
                Next

                Return result
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Public Function GetWMI(ByVal wmiClass As String, ByVal wmiProperty As String) As String
            Try
                Dim result As String = ""
                Dim mc As System.Management.ManagementClass = New System.Management.ManagementClass(wmiClass)
                Dim moc As System.Management.ManagementObjectCollection = mc.GetInstances()

                For Each mo As System.Management.ManagementObject In moc

                    If result Is "" Then

                        Try
                            result = mo(wmiProperty).ToString()
                            Exit For
                        Catch
                        End Try
                    End If
                Next

                Return result
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Public Function RandomString(ByVal length As Integer) As String
            Try
                Dim random As Random = New Random()
                Const chars As String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                Return New String(Enumerable.Repeat(chars, length).[Select](Function(s) s(random.[Next](s.Length))).ToArray())
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Public Function CreateMD5(ByVal input As String) As String
            Try

                Using md5 As System.Security.Cryptography.MD5 = System.Security.Cryptography.MD5.Create()
                    Dim inputBytes As Byte() = System.Text.Encoding.UTF8.GetBytes(input)
                    Dim hashBytes As Byte() = md5.ComputeHash(inputBytes)
                    Dim hashedString As String = BitConverter.ToString(hashBytes).Replace("-", "").ToLower()
                    Return hashedString
                End Using

            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Public Function createSHA512(ByVal plainText As String, ByVal salt As String) As String
            Try
                plainText &= salt
                Dim crypt = New System.Security.Cryptography.SHA512Managed()
                Dim hash = New System.Text.StringBuilder()
                Dim crypto As Byte() = crypt.ComputeHash(System.Text.Encoding.UTF8.GetBytes(plainText))

                For Each theByte As Byte In crypto
                    hash.Append(theByte.ToString("x2"))
                Next

                Return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(hash.ToString()))
            Catch ex As Exception
                Return Nothing
            End Try
        End Function

        Public Function ROT13(ByVal input As String) As String
            Dim result As Char() = input.ToCharArray()
            For i As Integer = 0 To result.Length - 1
                Dim temp As Integer = Asc(result(i))
                Select Case temp
                    Case 65 To 77, 97 To 109 'A - M
                        result(i) = Chr(temp + 13)
                    Case 78 To 90, 110 To 122 'N - Z
                        result(i) = Chr(temp - 13)
                End Select
            Next i
            Return New String(result)
        End Function

        Public Function GetComputerName() As String
            Return System.Environment.MachineName
        End Function

        Public Function PinPublicKey(ByVal sender As Object, ByVal certificate As System.Security.Cryptography.X509Certificates.X509Certificate, ByVal chain As System.Security.Cryptography.X509Certificates.X509Chain, ByVal sslPolicyErrors As System.Net.Security.SslPolicyErrors) As Boolean
            If Nothing Is certificate Then Return False
            Dim pk As String = createSHA512(certificate.GetPublicKeyString(), "")
            If pk.Equals(_PUB_KEY) Then Return True
            Return False
        End Function

        Public Function GetTime() As String
            Dim dateTimeX = New DateTime(Int16.Parse(DateTime.Now.ToString("yyyy")), Int16.Parse(DateTime.Now.ToString("MM")), Int16.Parse(DateTime.Now.ToString("dd")), Int16.Parse(DateTime.Now.ToString("HH")), Int16.Parse(DateTime.Now.ToString("mm")), Int16.Parse(DateTime.Now.ToString("ss")), DateTimeKind.Local)
            Dim epoch = New DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            Dim unixDateTime = (dateTimeX.ToUniversalTime() - epoch).TotalSeconds
            Return unixDateTime.ToString()
        End Function

        Public Function AESEncrypt(ByVal PlainText As String, ByVal KEY As String, ByVal IV As String) As String
            Try
                Dim dataencrypt As System.Security.Cryptography.AesCryptoServiceProvider = New System.Security.Cryptography.AesCryptoServiceProvider()
                dataencrypt.BlockSize = 128
                dataencrypt.KeySize = 128
                dataencrypt.Key = Convert.FromBase64String(KEY)
                dataencrypt.IV = Convert.FromBase64String(IV)
                dataencrypt.Padding = System.Security.Cryptography.PaddingMode.PKCS7
                dataencrypt.Mode = System.Security.Cryptography.CipherMode.CBC
                Dim crypto1 As System.Security.Cryptography.ICryptoTransform = dataencrypt.CreateEncryptor(dataencrypt.Key, dataencrypt.IV)
                Dim encrypteddata As Byte() = crypto1.TransformFinalBlock(System.Text.Encoding.UTF8.GetBytes(PlainText), 0, System.Text.Encoding.UTF8.GetBytes(PlainText).Length)
                crypto1.Dispose()
                Return Convert.ToBase64String(encrypteddata)
            Catch
                Return Nothing
            End Try
        End Function

        Public Function AESDecrypt(ByVal Cypher As String, ByVal KEY As String, ByVal IV As String) As String
            Try
                Dim keydecrypt As System.Security.Cryptography.AesCryptoServiceProvider = New System.Security.Cryptography.AesCryptoServiceProvider()
                keydecrypt.BlockSize = 128
                keydecrypt.KeySize = 128
                keydecrypt.Key = Convert.FromBase64String(KEY)
                keydecrypt.IV = Convert.FromBase64String(IV)
                keydecrypt.Padding = System.Security.Cryptography.PaddingMode.PKCS7
                keydecrypt.Mode = System.Security.Cryptography.CipherMode.CBC
                Dim crypto1 As System.Security.Cryptography.ICryptoTransform = keydecrypt.CreateDecryptor(keydecrypt.Key, keydecrypt.IV)
                Dim returnbytearray As Byte() = crypto1.TransformFinalBlock(Convert.FromBase64String(Cypher), 0, Convert.FromBase64String(Cypher).Length)
                crypto1.Dispose()
                Return System.Text.Encoding.UTF8.GetString(returnbytearray)
            Catch
                Return Nothing
            End Try
        End Function

        Public Function RSAEncrypt(ByVal content As String, ByVal ipublickey As String) As String
            Using rsa As RSA = New RSACng()
                Dim pr As PemReader = New PemReader(New StringReader(ipublickey))
                Dim publicKey As AsymmetricKeyParameter = CType(pr.ReadObject(), AsymmetricKeyParameter)
                Dim rsaParams As RSAParameters = DotNetUtilities.ToRSAParameters(CType(publicKey, RsaKeyParameters))
                rsa.ImportParameters(rsaParams)
                Dim encrypted As Byte() = rsa.Encrypt(Encoding.UTF8.GetBytes(content), RSAEncryptionPadding.OaepSHA1)
                Return Convert.ToBase64String(encrypted)
            End Using
        End Function

        Public Function GetHostIP(ByVal host As String) As String
            Try
                Dim hostEntry As System.Net.IPHostEntry
                Dim uri As String = System.Text.RegularExpressions.Regex.Replace(host, "^([a-zA-Z]+:\/\/)?([^\/]+)\/.*?$", "$2")
                hostEntry = System.Net.Dns.GetHostEntry(uri)

                If hostEntry.AddressList.Length > 0 Then
                    Dim ip = hostEntry.AddressList(0)
                    Dim s As System.Net.Sockets.Socket = New System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.IP)
                    s.Connect(ip, 80)
                    Return ip.ToString()
                End If

                Return Nothing
            Catch
                Return Nothing
            End Try
        End Function

        Public Function AppendUrlEncoded(ByVal name As String, ByVal value As String, ByVal Optional moreValues As Boolean = True) As String
            Dim builder As System.Text.StringBuilder = New System.Text.StringBuilder()
            builder.Append(System.Net.WebUtility.UrlEncode(name))
            builder.Append("=")
            builder.Append(System.Net.WebUtility.UrlEncode(value))

            If moreValues Then
                builder.Append("&")
            End If

            Return builder.ToString()
        End Function

        Public Function Base64Encode(ByVal Input As String) As String
            If String.IsNullOrEmpty(Input) Then Return ""
            Return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Input))
        End Function

        Public Function Base64Decode(ByVal Input As String) As String
            If String.IsNullOrEmpty(Input) Then Return ""
            Return System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Input))
        End Function

        Public Function CreateSHA256(ByVal Input As String) As String
            Try
                Dim crypt = New System.Security.Cryptography.SHA256Managed()
                Dim hash = New System.Text.StringBuilder()
                Dim crypto As Byte() = crypt.ComputeHash(Encoding.UTF8.GetBytes(Input))

                For Each theByte As Byte In crypto
                    hash.Append(theByte.ToString("x2"))
                Next

                Return hash.ToString()
            Catch
                Return Nothing
            End Try
        End Function

        Public Function CreateSHA1(ByVal Input As String) As String
            Try
                Dim hash = (New SHA1Managed()).ComputeHash(Encoding.UTF8.GetBytes(Input))
                Return String.Join("", hash.[Select](Function(b) b.ToString("x2")).ToArray())
            Catch
                Return Nothing
            End Try
        End Function

        Public Function DeviceId() As String
            Try
                Dim computer As String = GetComputerName()
                Dim graphic As String = GetGraphicCard()
                Dim windowsid As String = GetWindowsID()
                Dim ram As String = GetRAMcapacity()
                Dim hdd As String = GetHDDSerial()
                Dim bios As String = GetBiosSerial()
                Dim board As String = GetBoardMaker()
                Dim cpu As String = GetProcessId()
                Dim mac As String = GetMACAddress()
                Return CreateSHA256(computer & graphic & windowsid & ram & hdd & bios & board & cpu & mac)
            Catch
                Return Nothing
            End Try
        End Function

        Public Function ComputeHash(ByVal Text As String, ByVal Salt As String) As String
            If String.IsNullOrEmpty(Text) OrElse String.IsNullOrEmpty(Salt) Then Return Nothing

            If Salt.Length Mod 2 = 0 Then
                Return ROT13(Base64Encode(CreateSHA256(Base64Encode(Text) & CreateMD5(Salt))))
            Else
                Return ROT13(Base64Encode(CreateSHA256(CreateSHA1(Salt) & Base64Encode(Text))))
            End If
        End Function
    End Class
End Namespace
