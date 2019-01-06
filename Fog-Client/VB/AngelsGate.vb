Imports Newtonsoft.Json.Linq
Imports System
Imports System.Collections.Generic
Imports System.Text

Namespace AngelsGateLite

    ' AngelsGateLite by NIMIX3 (https://github.com/nimix3/AngelsGateLite) \\
    Public Class AngelsGate

        Protected EndPoint As String = Nothing

        Protected PublicKey As String = Nothing

        Protected sKEY As String = Nothing

        Protected sIV As String = Nothing

        Protected Request As String = Nothing

        Protected DeviceId As String = Nothing

        Protected Time As Integer = 0

        Protected TimeDiff As Integer = 0

        Protected Ssalt As String = Nothing

        Protected Data As Object = Nothing

        Protected Segment As String = Nothing

        Protected DateY As String = "2019"

        Public Sub setDateY(ByVal datey As String)
            Me.DateY = datey
        End Sub

        Public Sub setsKey(ByVal skey As String)
            Me.sKEY = skey
        End Sub

        Public Sub setsIV(ByVal siv As String)
            Me.sIV = siv
        End Sub

        Public Sub setEndPoint(ByVal endpoint As String)
            Me.EndPoint = endpoint
        End Sub

        Public Sub setPublicKey(ByVal pk As String)
            Me.PublicKey = pk
        End Sub

        Public Sub setRequest(ByVal req As String)
            Me.Request = req
        End Sub

        Public Sub setDeviceId(ByVal device As String)
            Me.DeviceId = device
        End Sub

        Public Sub setSegment(ByVal segment As String)
            Me.Segment = segment
        End Sub

        Public Overloads Sub setData(ByVal data() As String)
            Me.Data = data
        End Sub

        Public Overloads Sub setData(ByVal data As Dictionary(Of String, String))
            Me.Data = data
        End Sub

        Public Overloads Sub setData(ByVal data As Object)
            Me.Data = data
        End Sub

        Public Sub setTimeDiff(ByVal Timed As Integer)
            Me.TimeDiff = Timed
        End Sub

        Public Function SendRequest(Optional ByVal serverIP As String = Nothing) As Dictionary(Of String, Object)
            Try
                If (String.IsNullOrEmpty(Me.sKEY) _
                            OrElse String.IsNullOrEmpty(Me.sIV) _
                            OrElse String.IsNullOrEmpty(Me.EndPoint) _
                            OrElse String.IsNullOrEmpty(Me.Request) _
                            OrElse String.IsNullOrEmpty(Me.PublicKey)) Then
                    Throw New Exception
                End If

                Dim Utils As AngelsGateUtils = New AngelsGateUtils

                If Not String.IsNullOrEmpty(Utils._PUB_KEY) Then
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = AddressOf Utils.PinPublicKey
                End If

                If Not String.IsNullOrEmpty(serverIP) Then
                    If (Utils.GetHostIP(Me.EndPoint) <> serverIP) Then
                        Return Nothing
                    End If
                End If

                Dim Json = New System.Web.Script.Serialization.JavaScriptSerializer
                Dim Encapsulation As New Dictionary(Of String, Object)

                Encapsulation("Request") = Me.Request

                If (String.IsNullOrEmpty(Me.DeviceId)) Then
                    Me.DeviceId = Utils.DeviceId()
                End If
                Encapsulation("Deviceid") = Me.DeviceId

                If (String.IsNullOrEmpty(Me.Ssalt)) Then
                    Me.Ssalt = Utils.RandomString(New Random().Next(14, 16))
                End If
                Encapsulation("Ssalt") = Utils.RSAEncrypt(Me.Ssalt, Me.PublicKey)

                Dim rKEY As String = (Me.Ssalt & Utils.Base64Decode(Me.sKEY))
                rKEY = Utils.Base64Encode(rKEY.Substring(0, 16))
                Encapsulation("Data") = Utils.AESEncrypt(Utils.Base64Encode(Json.Serialize(Me.Data)), rKEY, Me.sIV)

                If (Me.Time < 1) Then
                    Encapsulation("Time") = Int32.Parse(Utils.GetTime) + Me.TimeDiff
                Else
                    Encapsulation("Time") = Me.Time + Me.TimeDiff
                End If

                If (String.IsNullOrEmpty(Me.Segment)) Then
                    Encapsulation("Segment") = New Random().Next(10, Int32.MaxValue).ToString()
                Else
                    Encapsulation("Segment") = Me.Segment
                End If

                Encapsulation("Signature") = Utils.ComputeHash(Me.Ssalt & Me.DateY & Me.Request & Utils.Base64Encode(Json.Serialize(Me.Data)) & Me.DeviceId, Me.Ssalt)

                Dim postBytes() As Byte = New System.Text.UTF8Encoding().GetBytes(Utils.AESEncrypt(Json.Serialize(Encapsulation), Me.sKEY, Me.sIV))
                Dim request As System.Net.WebRequest = CType(System.Net.WebRequest.Create(Me.EndPoint), System.Net.WebRequest)
                request.Method = "POST"
                request.ContentType = "application/x-www-form-urlencoded"
                request.ContentLength = postBytes.Length
                Dim postStream As System.IO.Stream = request.GetRequestStream()
                postStream.Write(postBytes, 0, postBytes.Length)
                Dim Response As String = Nothing
                Using resp = request.GetResponse()
                    Response = New System.IO.StreamReader(resp.GetResponseStream(), System.Text.Encoding.UTF8).ReadToEnd()
                End Using
                postStream.Flush()
                postStream.Close()

                If String.IsNullOrEmpty(Response) Then
                    Return Nothing
                ElseIf (Response.Contains("ERROR_SERVER_FATAL") OrElse Response.Contains("ERROR_INPUT_")) Then
                    Return Nothing
                Else
                    Response = Utils.AESDecrypt(Response, rKEY, Me.sIV)
                    Dim items As JToken = JObject.Parse(Response)
                    Dim Result As New Dictionary(Of String, Object)
                    Dim rData As String = ""

                    If (Not (items("Data").ToString()) Is Nothing) Then
                        rData = Utils.Base64Decode(items("Data").ToString())
                    End If
                    Result("Data") = Utils.Base64Decode(items("Data").ToString())

                    If (Not items("Signature").ToString() Is Nothing) Then
                        Result("Signature") = items("Signature").ToString()
                    End If

                    If (Not items("Deviceid").ToString() Is Nothing) Then
                        Result("Deviceid") = items("Deviceid").ToString()
                    End If

                    If (Not items("Token").ToString() Is Nothing) Then
                        Result("Token") = items("Token").ToString()
                    End If

                    If (Not items("Segment").ToString() Is Nothing) Then
                        Result("Segment") = items("Segment").ToString()
                    End If

                    If (Utils.CreateMD5(Me.DeviceId) <> Result("Deviceid").ToString()) Then
                        Return Nothing
                    End If

                    If (Utils.ComputeHash(Me.Ssalt & items("Data").ToString() & Me.DateY & items("Segment").ToString() & Me.DeviceId, items("Token").ToString()) <> items("Signature").ToString()) Then
                        Return Nothing
                    End If

                    If rData.Contains("ERROR_INPUT_INVALIDTIME") Then
                        Dim Encapsulation2 As New Dictionary(Of String, Object)
                        Encapsulation2("Request") = "TimeSync"
                        Encapsulation2("Deviceid") = Me.DeviceId
                        postBytes = New System.Text.UTF8Encoding().GetBytes(Utils.AESEncrypt(Json.Serialize(Encapsulation2), Me.sKEY, Me.sIV))
                        request = CType(System.Net.WebRequest.Create(Me.EndPoint), System.Net.WebRequest)
                        request.Method = "POST"
                        request.ContentType = "application/x-www-form-urlencoded"
                        request.ContentLength = postBytes.Length
                        postStream = request.GetRequestStream()
                        postStream.Write(postBytes, 0, postBytes.Length)
                        Using resp = request.GetResponse()
                            Response = New System.IO.StreamReader(resp.GetResponseStream(), System.Text.Encoding.UTF8).ReadToEnd()
                        End Using
                        postStream.Flush()
                        postStream.Close()

                        If String.IsNullOrEmpty(Response) Then
                            Return Nothing
                        End If

                        Dim timedf As Integer
                        If Integer.TryParse(Response, timedf) Then
                            Me.TimeDiff = (timedf - Int32.Parse(Utils.GetTime))
                            Return Me.SendRequest(serverIP)
                        Else
                            Return Nothing
                        End If
                    ElseIf rData.Contains("ERROR_INPUT_") Then
                        Return Nothing
                    Else
                        Return Result
                    End If
                End If

            Catch ex As Exception
                Return Nothing
            End Try

        End Function
    End Class
End Namespace
