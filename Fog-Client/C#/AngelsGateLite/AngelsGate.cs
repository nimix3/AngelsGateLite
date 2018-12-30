using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace AngelsGateLite
{
    // AngelsGateLite by NIMIX3 (https://github.com/nimix3/AngelsGateLite) \\
    public class AngelsGate
    {
        protected string EndPoint = null;
        protected string PublicKey = null;
        protected string sKEY = null;
        protected string sIV = null;
        protected string Request = null;
        protected string DeviceId = null;
        protected int Time = 0;
        protected int TimeDiff = 0;
        protected string Ssalt = null;
        protected object Data = null;
        protected string Segment = null;
        protected string DateY = "2018";

        public void setDateY(string datey)
        {
            DateY = datey;
        }

        public void setsKey(string skey)
        {
            sKEY = skey;
        }

        public void setsIV(string siv)
        {
            sIV = siv;
        }

        public void setEndPoint(string endpoint)
        {
            EndPoint = endpoint;
        }

        public void setPublicKey(string pk)
        {
            PublicKey = pk;
        }

        public void setRequest(string req)
        {
            Request = req;
        }

        public void setDeviceId(string device)
        {
            DeviceId = device;
        }

        public void setSegment(string segment)
        {
            Segment = segment;
        }

        public void setData(string[] data)
        {
            Data = data;
        }

        public void setData(Dictionary<string, string> data)
        {
            Data = data;
        }

        public void setData(object data)
        {
            Data = data;
        }

        public void setTimeDiff(int Timed)
        {
            TimeDiff = Timed;
        }

        public Dictionary<string, object> SendRequest(string serverIP = null)
        {
            try
            {
                if (string.IsNullOrEmpty(sKEY) || string.IsNullOrEmpty(sIV) || string.IsNullOrEmpty(EndPoint) || string.IsNullOrEmpty(Request) || string.IsNullOrEmpty(PublicKey))
                    throw new Exception();

                AngelsGateUtils Utils = new AngelsGateUtils();

                if (!String.IsNullOrEmpty(Utils._PUB_KEY))
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = Utils.PinPublicKey;
                if (!String.IsNullOrEmpty(serverIP))
                    if (Utils.GetHostIP(EndPoint) != serverIP)
                        return null;

                var Json = new System.Web.Script.Serialization.JavaScriptSerializer();
                var Encapsulation = new Dictionary<string, object> { };

                Encapsulation["Request"] = Request;

                DeviceId = string.IsNullOrEmpty(DeviceId) ? Utils.DeviceId() : DeviceId;
                Encapsulation["Deviceid"] = DeviceId;

                Ssalt = string.IsNullOrEmpty(Ssalt) ? Utils.RandomString(new Random().Next(14,16)) : Ssalt;
                Encapsulation["Ssalt"] = Utils.RSAEncrypt(Ssalt,PublicKey);

                string rKEY = Ssalt + Utils.Base64Decode(sKEY);
                rKEY = Utils.Base64Encode(rKEY.Substring(0, 16));
                Encapsulation["Data"] = Utils.AESEncrypt(Utils.Base64Encode(Json.Serialize(Data)), rKEY, sIV);

                Encapsulation["Time"] = (Time < 1 ? Int32.Parse(Utils.GetTime()) : Time) + TimeDiff;
                Encapsulation["Segment"] = string.IsNullOrEmpty(Segment) ? new Random().Next(10,Int32.MaxValue).ToString() : Segment;
                Encapsulation["Signature"] = Utils.ComputeHash(Ssalt + DateY + Request + Utils.Base64Encode(Json.Serialize(Data)) + DeviceId, Ssalt);

                byte[] postBytes = new System.Text.UTF8Encoding().GetBytes(Utils.AESEncrypt(Json.Serialize(Encapsulation), sKEY, sIV));

                System.Net.WebRequest request = (System.Net.WebRequest)System.Net.WebRequest.Create(EndPoint);
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = postBytes.Length;
                System.IO.Stream postStream = request.GetRequestStream();
                postStream.Write(postBytes, 0, postBytes.Length);
                string Response = null;
                using (var resp = request.GetResponse())
                {
                    Response = new System.IO.StreamReader(resp.GetResponseStream(), System.Text.Encoding.UTF8).ReadToEnd();
                }
                postStream.Flush();
                postStream.Close();

                if(string.IsNullOrEmpty(Response))
                {
                    return null;
                }
                else if (Response.Contains("ERROR_SERVER_FATAL") || Response.Contains("ERROR_INPUT_"))
                {
                    return null;
                }
                else
                {
                    Response = Utils.AESDecrypt(Response, rKEY, sIV);
                    JToken items = JObject.Parse(Response);
                    var Result = new Dictionary<string, object> { };
                    string rData = "";
                    if (items["Data"].ToString() != null)
                        Result["Data"] = rData = Utils.Base64Decode(items["Data"].ToString());
                    if (items["Signature"].ToString() != null)
                        Result["Signature"] = items["Signature"].ToString();
                    if (items["Deviceid"].ToString() != null)
                        Result["Deviceid"] = items["Deviceid"].ToString();
                    if (items["Token"].ToString() != null)
                        Result["Token"] = items["Token"].ToString();
                    if (items["Segment"].ToString() != null)
                        Result["Segment"] = items["Segment"].ToString();

                    if(Utils.CreateMD5(DeviceId) != Result["Deviceid"].ToString())
                    {
                        return null;
                    }
                    if (Utils.ComputeHash(Ssalt + items["Data"].ToString() + DateY + items["Segment"].ToString() + DeviceId , items["Token"].ToString()) != items["Signature"].ToString())
                    {
                        return null;
                    }
                    if (rData.Contains("ERROR_INPUT_INVALIDTIME"))
                    {
                        var Encapsulation2 = new Dictionary<string, object> { };
                        Encapsulation2["Request"] = "TimeSync";
                        Encapsulation2["Deviceid"] = DeviceId;
                        postBytes = new System.Text.UTF8Encoding().GetBytes(Utils.AESEncrypt(Json.Serialize(Encapsulation2), sKEY, sIV));
                        request = (System.Net.WebRequest)System.Net.WebRequest.Create(EndPoint);
                        request.Method = "POST";
                        request.ContentType = "application/x-www-form-urlencoded";
                        request.ContentLength = postBytes.Length;
                        postStream = request.GetRequestStream();
                        postStream.Write(postBytes, 0, postBytes.Length);
                        using (var resp = request.GetResponse())
                        {
                            Response = new System.IO.StreamReader(resp.GetResponseStream(), System.Text.Encoding.UTF8).ReadToEnd();
                        }
                        postStream.Flush();
                        postStream.Close();
                        if(string.IsNullOrEmpty(Response))
                        {
                            return null;
                        }
                        int timedf;
                        if (int.TryParse(Response, out timedf))
                        {
                            TimeDiff = timedf - Int32.Parse(Utils.GetTime());
                            return SendRequest(serverIP);
                        }
                        else
                        {
                            return null;
                        }
                    }
                    else if (rData.Contains("ERROR_INPUT_"))
                    {
                        return null;
                    }
                    else
                    {
                        return Result;
                    }
                }
            }
            catch (Exception ex)
            {
                return null;
            }
        }
    }
}