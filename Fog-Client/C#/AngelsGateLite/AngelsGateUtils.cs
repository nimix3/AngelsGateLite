using AntiDBG;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AngelsGateLite
{
    // AngelsGateLite by NIMIX3 (https://github.com/nimix3/AngelsGateLite) \\
    public class AngelsGateUtils
    {
        public string _PUB_KEY;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        static extern bool GetPhysicallyInstalledSystemMemory(out long TotalMemoryInKilobytes);
        public void setupHPKP(string CertSig)
        {
            _PUB_KEY = CertSig;
        }
        public string GetProcessId()
        {
            try
            {
                string retVal = GetWMI("Win32_Processor", "UniqueId");
                if (retVal == "")
                {
                    retVal = GetWMI("Win32_Processor", "ProcessorId");
                    if (retVal == "")
                    {
                        retVal = GetWMI("Win32_Processor", "Name");
                        if (retVal == "")
                        {
                            retVal = GetWMI("Win32_Processor", "Manufacturer");
                        }
                        retVal += GetWMI("Win32_Processor", "MaxClockSpeed");
                    }
                }
                return CreateMD5(retVal);
            }
            catch (Exception ex)
            { return null; }
        }

        public string GetBiosSerial()
        {
            string ret = null;
            try
            {
                ret = this.CreateMD5(this.GetWMI("Win32_BIOS", "Manufacturer")
                + this.GetWMI("Win32_BIOS", "SMBIOSBIOSVersion")
                + this.GetWMI("Win32_BIOS", "IdentificationCode")
                + this.GetWMI("Win32_BIOS", "SerialNumber")
                + this.GetWMI("Win32_BIOS", "ReleaseDate")
                + this.GetWMI("Win32_BIOS", "Version"));
            }
            catch { ret = null; }
            if (string.IsNullOrEmpty(ret))
                return this.GetProcessId();
            else
                return ret;
        }

        public string GetUUID()
        {
            System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_ComputerSystemProduct");
            foreach (System.Management.ManagementObject wmi in searcher.Get())
            {
                try
                {
                    return wmi.GetPropertyValue("UUID").ToString();
                }
                catch (Exception ex) { return null; }
            }
            return null;
        }

        public string GetMACAddress()
        {
            string ret = null;
            try
            {
                ret = this.CreateMD5(GetWMI("Win32_NetworkAdapterConfiguration", "MACAddress", "IPEnabled"));
            }
            catch { ret = null; }
            if (string.IsNullOrEmpty(ret))
                return this.GetProcessId();
            else
                return ret;
        }

        public string GetHDDSerial()
        {
            string ret = null;
            try
            {
                ret = this.CreateMD5(this.GetWMI("Win32_DiskDrive", "Model")
                + this.GetWMI("Win32_DiskDrive", "Manufacturer")
                + this.GetWMI("Win32_DiskDrive", "Signature")
                + this.GetWMI("Win32_DiskDrive", "TotalHeads"));
            }
            catch { ret = null; }
            if (string.IsNullOrEmpty(ret))
                return this.GetProcessId();
            else
                return ret;
        }

        public string GetBoardMaker()
        {
            string ret = null;
            try
            {
                ret = this.CreateMD5(this.GetWMI("Win32_BaseBoard", "Model")
                + this.GetWMI("Win32_BaseBoard", "Manufacturer")
                + this.GetWMI("Win32_BaseBoard", "Name")
                + this.GetWMI("Win32_BaseBoard", "SerialNumber"));
            }
            catch { ret = null; }
            if (string.IsNullOrEmpty(ret))
                return this.GetProcessId();
            else
                return ret;
        }

        public bool DetectVM()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
                {
                    using (var items = searcher.Get())
                    {
                        foreach (var item in items)
                        {
                            string manufacturer = item["Manufacturer"].ToString().ToLower();
                            if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                                || manufacturer.Contains("vmware")
                                || item["Model"].ToString() == "VirtualBox")
                            {
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
            catch (Exception ex) { return true; }
        }

        public string GetOSSerial()
        {
            try
            {
                System.Management.ManagementObject os = new System.Management.ManagementObject("Win32_OperatingSystem=@");
                string serial = (string)os["SerialNumber"];
                return serial;
            }
            catch (Exception ex)
            { return null; }
        }

        public bool DetectDBG()
        {
            try
            {
                System.Diagnostics.Process[] re = System.Diagnostics.Process.GetProcessesByName("Reflector");
                System.Diagnostics.Process[] pname = System.Diagnostics.Process.GetProcessesByName("CFF Explorer");
                System.Diagnostics.Process[] OLLYDBG = System.Diagnostics.Process.GetProcessesByName("Ollydbg");
                System.Diagnostics.Process[] ImmunityDebugger = System.Diagnostics.Process.GetProcessesByName("ImmunityDebugger");
                System.Diagnostics.Process[] W32DSM89 = System.Diagnostics.Process.GetProcessesByName("W32DSM89");
                System.Diagnostics.Process[] DeDe = System.Diagnostics.Process.GetProcessesByName("DeDe");
                System.Diagnostics.Process[] ObsidianGUI = System.Diagnostics.Process.GetProcessesByName("ObsidianGUI");
                System.Diagnostics.Process[] exeinfope = System.Diagnostics.Process.GetProcessesByName("exeinfope");
                System.Diagnostics.Process[] AT4RE_FastScanner = System.Diagnostics.Process.GetProcessesByName("AT4RE_FastScanner");
                if (re.Length != 0 || pname.Length != 0 || OLLYDBG.Length != 0 || ImmunityDebugger.Length != 0 || W32DSM89.Length != 0 || DeDe.Length != 0 || exeinfope.Length != 0 || AT4RE_FastScanner.Length != 0 || ObsidianGUI.Length != 0)
                {
                    return true;
                }
                if (AntiManagedProfiler.Initialize())
                {
                    if (AntiManagedProfiler.IsProfilerAttached)
                    {
                        AntiManagedProfiler.PreventActiveProfilerFromReceivingProfilingMessages();
                        return true;
                    }
                }
                if (AntiManagedDebugger.Initialize())
                {
                    if (Debugger.IsAttached)
                        return true;
                }
                bool isDebuggerPresent = false;
                CheckRemoteDebuggerPresent(System.Diagnostics.Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
                return isDebuggerPresent;
            }
            catch (Exception ex)
            { return true; }
        }

        public string GetRAMcapacity()
        {
            try
            {
                long memKb;
                GetPhysicallyInstalledSystemMemory(out memKb);
                return memKb.ToString();
            }
            catch (Exception ex)
            { return null; }
        }

        public string GetWindowsID()
        {
            try
            {
                string x64Result = string.Empty;
                string x86Result = string.Empty;
                Microsoft.Win32.RegistryKey keyBaseX64 = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
                Microsoft.Win32.RegistryKey keyBaseX86 = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32);
                Microsoft.Win32.RegistryKey keyX64 = keyBaseX64.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", Microsoft.Win32.RegistryKeyPermissionCheck.ReadSubTree);
                Microsoft.Win32.RegistryKey keyX86 = keyBaseX86.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", Microsoft.Win32.RegistryKeyPermissionCheck.ReadSubTree);
                object resultObjX64 = keyX64.GetValue("MachineGuid", (object)"default");
                object resultObjX86 = keyX86.GetValue("MachineGuid", (object)"default");
                keyX64.Close();
                keyX86.Close();
                keyBaseX64.Close();
                keyBaseX86.Close();
                keyX64.Dispose();
                keyX86.Dispose();
                keyBaseX64.Dispose();
                keyBaseX86.Dispose();
                keyX64 = null;
                keyX86 = null;
                keyBaseX64 = null;
                keyBaseX86 = null;
                if (resultObjX64 != null && resultObjX64.ToString() != "default")
                {
                    return resultObjX64.ToString();
                }
                if (resultObjX86 != null && resultObjX86.ToString() != "default")
                {
                    return resultObjX86.ToString();
                }
                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public string GetGraphicCard()
        {
            string ret = null;
            try
            {
                ret = this.CreateMD5(this.GetWMI("Win32_VideoController", "Name")
                + this.GetWMI("Win32_VideoController", "DriverVersion"));
            }
            catch { ret = null; }
            if (string.IsNullOrEmpty(ret))
                return this.GetProcessId();
            else
                return ret;
        }

        private static string GetWMI(string wmiClass, string wmiProperty, string wmiMustBeTrue)
        {
            try
            {
                string result = "";
                System.Management.ManagementClass mc = new System.Management.ManagementClass(wmiClass);
                System.Management.ManagementObjectCollection moc = mc.GetInstances();
                foreach (System.Management.ManagementObject mo in moc)
                {
                    if (mo[wmiMustBeTrue].ToString() == "True")
                    {
                        if (result == "")
                        {
                            try
                            {
                                result = mo[wmiProperty].ToString();
                                break;
                            }
                            catch
                            {
                            }
                        }
                    }
                }
                return result;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public string GetWMI(string wmiClass, string wmiProperty)
        {
            try
            {
                string result = "";
                System.Management.ManagementClass mc = new System.Management.ManagementClass(wmiClass);
                System.Management.ManagementObjectCollection moc = mc.GetInstances();
                foreach (System.Management.ManagementObject mo in moc)
                {
                    if (result == "")
                    {
                        try
                        {
                            result = mo[wmiProperty].ToString();
                            break;
                        }
                        catch
                        {
                        }
                    }
                }
                return result;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public string RandomString(int length)
        {
            try
            {
                Random random = new Random();
                const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                return new string(Enumerable.Repeat(chars, length)
                  .Select(s => s[random.Next(s.Length)]).ToArray());
            }
            catch (Exception ex)
            { return null; }
        }

        public string CreateMD5(string input)
        {
            try
            {
                using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
                {
                    byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);
                    byte[] hashBytes = md5.ComputeHash(inputBytes);
                    string hashedString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                    return hashedString;
                }
            }
            catch (Exception ex)
            { return null; }
        }

        public string createSHA512(string plainText, string salt)
        {
            try
            {
                plainText += salt;
                var crypt = new System.Security.Cryptography.SHA512Managed();
                var hash = new System.Text.StringBuilder();
                byte[] crypto = crypt.ComputeHash(System.Text.Encoding.UTF8.GetBytes(plainText));
                foreach (byte theByte in crypto)
                {
                    hash.Append(theByte.ToString("x2"));
                }
                return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(hash.ToString()));
            }
            catch (Exception ex)
            { return null; }
        }

        public string ROT13(string input)
        {
            return !string.IsNullOrEmpty(input) ? new string(input.ToCharArray().Select(s => { return (char)((s >= 97 && s <= 122) ? ((s + 13 > 122) ? s - 13 : s + 13) : (s >= 65 && s <= 90 ? (s + 13 > 90 ? s - 13 : s + 13) : s)); }).ToArray()) : input;
        }

        public string GetComputerName()
        {
            return System.Environment.MachineName;
        }

        public bool PinPublicKey(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
        {
            if (null == certificate)
                return false;
            String pk = createSHA512(certificate.GetPublicKeyString(), "");
            if (pk.Equals(_PUB_KEY))
                return true;
            return false;
        }

        public string GetTime()
        {
            var dateTime = new DateTime(Int16.Parse(DateTime.Now.ToString("yyyy")), Int16.Parse(DateTime.Now.ToString("MM")), Int16.Parse(DateTime.Now.ToString("dd")), Int16.Parse(DateTime.Now.ToString("HH")), Int16.Parse(DateTime.Now.ToString("mm")), Int16.Parse(DateTime.Now.ToString("ss")), DateTimeKind.Local);
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var unixDateTime = (dateTime.ToUniversalTime() - epoch).TotalSeconds;
            return unixDateTime.ToString();
        }

        public string AESEncrypt(string PlainText, string KEY, string IV)
        {
            try
            {
                System.Security.Cryptography.AesCryptoServiceProvider dataencrypt = new System.Security.Cryptography.AesCryptoServiceProvider();
                dataencrypt.BlockSize = 128;
                dataencrypt.KeySize = 128;
                dataencrypt.Key = Convert.FromBase64String(KEY);
                dataencrypt.IV = Convert.FromBase64String(IV);
                dataencrypt.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                dataencrypt.Mode = System.Security.Cryptography.CipherMode.CBC;
                System.Security.Cryptography.ICryptoTransform crypto1 = dataencrypt.CreateEncryptor(dataencrypt.Key, dataencrypt.IV);
                byte[] encrypteddata = crypto1.TransformFinalBlock(System.Text.Encoding.UTF8.GetBytes(PlainText), 0, System.Text.Encoding.UTF8.GetBytes(PlainText).Length);
                crypto1.Dispose();
                return Convert.ToBase64String(encrypteddata);
            }
            catch
            {
                return null;
            }
        }

        public string AESDecrypt(string Cypher, string KEY, string IV)
        {
            try
            {
                System.Security.Cryptography.AesCryptoServiceProvider keydecrypt = new System.Security.Cryptography.AesCryptoServiceProvider();
                keydecrypt.BlockSize = 128;
                keydecrypt.KeySize = 128;
                keydecrypt.Key = Convert.FromBase64String(KEY);
                keydecrypt.IV = Convert.FromBase64String(IV);
                keydecrypt.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                keydecrypt.Mode = System.Security.Cryptography.CipherMode.CBC;
                System.Security.Cryptography.ICryptoTransform crypto1 = keydecrypt.CreateDecryptor(keydecrypt.Key, keydecrypt.IV);
                byte[] returnbytearray = crypto1.TransformFinalBlock(Convert.FromBase64String(Cypher), 0, Convert.FromBase64String(Cypher).Length);
                crypto1.Dispose();
                return System.Text.Encoding.UTF8.GetString(returnbytearray);
            }
            catch
            {
                return null;
            }
        }

        public string RSAEncrypt(string content, string publickey)
        {
            using (RSA rsa = new RSACng())
            {
                PemReader pr = new PemReader(new StringReader(publickey));
                AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);
                rsa.ImportParameters(rsaParams);
                byte[] encrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(content), RSAEncryptionPadding.OaepSHA1);
                return Convert.ToBase64String(encrypted);
            }
        }
        
        public string RSAEncryptBC(string content, string publicKey)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(content);
            var encryptEngine = new OaepEncoding(new RsaEngine());
            using (var txtreader = new StringReader(publicKey))
            {
                var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();
                encryptEngine.Init(true, keyParameter);
            }
            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }

        public string GetHostIP(string host)
        {
            try
            {
                System.Net.IPHostEntry hostEntry;
                string uri = System.Text.RegularExpressions.Regex.Replace(host, @"^([a-zA-Z]+:\/\/)?([^\/]+)\/.*?$", "$2");
                hostEntry = System.Net.Dns.GetHostEntry(uri);
                if (hostEntry.AddressList.Length > 0)
                {
                    var ip = hostEntry.AddressList[0];
                    System.Net.Sockets.Socket s = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.IP);
                    s.Connect(ip, 80);
                    return ip.ToString();
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        public string AppendUrlEncoded(string name, string value, bool moreValues = true)
        {
            System.Text.StringBuilder builder = new System.Text.StringBuilder();
            builder.Append(System.Net.WebUtility.UrlEncode(name));
            builder.Append("=");
            builder.Append(System.Net.WebUtility.UrlEncode(value));
            if (moreValues)
            {
                builder.Append("&");
            }
            return builder.ToString();
        }

        public string Base64Encode(string Input)
        {
            if (string.IsNullOrEmpty(Input))
                return "";
            return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Input));
        }

        public string Base64Decode(string Input)
        {
            if (string.IsNullOrEmpty(Input))
                return "";
            return System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Input));
        }

        public string CreateSHA256(string Input)
        {
            try
            {
                var crypt = new System.Security.Cryptography.SHA256Managed();
                var hash = new System.Text.StringBuilder();
                byte[] crypto = crypt.ComputeHash(Encoding.UTF8.GetBytes(Input));
                foreach (byte theByte in crypto)
                {
                    hash.Append(theByte.ToString("x2"));
                }
                return hash.ToString();
            }
            catch
            {
                return null;
            }
        }

        public string CreateSHA1(string Input)
        {
            try
            {
                var hash = (new SHA1Managed()).ComputeHash(Encoding.UTF8.GetBytes(Input));
                return string.Join("", hash.Select(b => b.ToString("x2")).ToArray());
            }
            catch
            {
                return null;
            }
        }

        public string DeviceId()
        {
            try
            {
                string computer = GetComputerName();
                string graphic = GetGraphicCard();
                string windowsid = GetWindowsID();
                string ram = GetRAMcapacity();
                string hdd = GetHDDSerial();
                string bios = GetBiosSerial();
                string board = GetBoardMaker();
                string cpu = GetProcessId();
                string mac = GetMACAddress();
                return CreateSHA256(computer + graphic + windowsid + ram + hdd + bios + board + cpu + mac);
            }
            catch
            {
                return null;
            }
        }

        public string ComputeHash(string Text, string Salt)
        {
            if (string.IsNullOrEmpty(Text) || string.IsNullOrEmpty(Salt))
                return null;
            if(Salt.Length % 2 == 0)
            {
                return ROT13(Base64Encode(CreateSHA256(Base64Encode(Text) + CreateMD5(Salt))));
            }
            else
            {
                return ROT13(Base64Encode(CreateSHA256(CreateSHA1(Salt) + Base64Encode(Text))));
            }
        }
    }
}
