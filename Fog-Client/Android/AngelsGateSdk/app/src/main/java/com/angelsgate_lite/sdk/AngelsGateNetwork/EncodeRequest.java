package com.angelsgate_lite.sdk.AngelsGateNetwork;

import android.content.Context;

import com.angelsgate_lite.sdk.AngelsGateUtils.AESCrypt;
import com.angelsgate_lite.sdk.AngelsGateUtils.AngelGateConstants;
import com.angelsgate_lite.sdk.AngelsGateUtils.Base64Utils;
import com.angelsgate_lite.sdk.AngelsGateUtils.EncodeAlgorithmUtils;
import com.angelsgate_lite.sdk.AngelsGateUtils.RSACrypt;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import okhttp3.Request;
import okhttp3.RequestBody;
import okio.Buffer;

public class EncodeRequest {


    ///okHttp3 Request
    public static Request EncodeRequest(Request OkHttpRequest, long timestamp, String deviceId, long Segment, String Ssalt, String nameMethode, boolean isArrayRequest, Context ctx) throws UnsupportedEncodingException, GeneralSecurityException {
        RequestBody requestBody = OkHttpRequest.body();
        String rawJson = bodyToString(requestBody);


        String Request = nameMethode;
        String DeviceId = deviceId;
        boolean isArray = isArrayRequest;


        if (!Request.equals(AngelGateConstants.SignalMethodName)) {


            String ObjectORArray = "";

            if (isArray) {
                ObjectORArray = "Array";
            } else {
                ObjectORArray = "Object";
            }


            JSONObject originalRequestJsonObject = null;
            JSONArray originalRequestJsonArray = null;


            if (rawJson.length() != 0) {
                try {

                    if (ObjectORArray.equals("Object")) {
                        originalRequestJsonObject = new JSONObject(rawJson);
                    } else if (ObjectORArray.equals("Array")) {
                        originalRequestJsonArray = new JSONArray(rawJson);
                    }


                } catch (JSONException e) {
                    e.printStackTrace();


                }
            }


            JSONObject ModifiedRequestJsonObject = new JSONObject();


            try {


                ////////change

                String iv = AngelGateConstants.iv;
                String secretkey = AngelGateConstants.secretkey;
                String KeyRotational = EncodeAlgorithmUtils.KeyRotational(String.valueOf(Ssalt), secretkey);

                String data = "";

                if (ObjectORArray.equals("Object")) {

                    if (originalRequestJsonObject != null) {
                        try {
                            data = AESCrypt.encrypt(KeyRotational, Base64Utils.toBase64(originalRequestJsonObject.toString()), iv);
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    } else {

                        try {
                            data = AESCrypt.encrypt(KeyRotational, Base64Utils.toBase64(""), iv);
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    }


                } else if (ObjectORArray.equals("Array")) {


                    if (originalRequestJsonArray != null) {
                        try {
                            data = AESCrypt.encrypt(KeyRotational, Base64Utils.toBase64(originalRequestJsonArray.toString()), iv);
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    } else {

                        try {
                            data = AESCrypt.encrypt(KeyRotational, Base64Utils.toBase64(""), iv);
                        } catch (GeneralSecurityException e) {
                            e.printStackTrace();
                        }
                    }


                }


                ///////change
                ModifiedRequestJsonObject.put("Request", Request);
                ModifiedRequestJsonObject.put("Data", data);
                ModifiedRequestJsonObject.put("Deviceid", DeviceId);
                ModifiedRequestJsonObject.put("Ssalt", RSACrypt.RSAEncrypt(Ssalt));
                ModifiedRequestJsonObject.put("Time", timestamp);
                ModifiedRequestJsonObject.put("Segment", Segment);


                int currentYear = Calendar.getInstance().get(Calendar.YEAR);


                try {


                    if (ObjectORArray.equals("Object")) {

                        if (originalRequestJsonObject != null) {

                            ModifiedRequestJsonObject.put("Signature", EncodeAlgorithmUtils.computeHash(String.valueOf(Ssalt) + currentYear + Request + Base64Utils.toBase64(originalRequestJsonObject.toString()) + DeviceId, String.valueOf(Ssalt)));

                        } else {
                            ModifiedRequestJsonObject.put("Signature", EncodeAlgorithmUtils.computeHash(String.valueOf(Ssalt) + currentYear + Request + Base64Utils.toBase64("") + DeviceId, String.valueOf(Ssalt)));

                        }


                    } else if (ObjectORArray.equals("Array")) {


                        if (originalRequestJsonArray != null) {

                            ModifiedRequestJsonObject.put("Signature", EncodeAlgorithmUtils.computeHash(String.valueOf(Ssalt) + currentYear + Request + Base64Utils.toBase64(originalRequestJsonArray.toString()) + DeviceId, String.valueOf(Ssalt)));

                        } else {
                            ModifiedRequestJsonObject.put("Signature", EncodeAlgorithmUtils.computeHash(String.valueOf(Ssalt) + currentYear + Request + Base64Utils.toBase64("" )+ DeviceId, String.valueOf(Ssalt)));

                        }


                    }


                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }


            } catch (JSONException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            }


            String iv = AngelGateConstants.iv;
            String secretkey = AngelGateConstants.secretkey;


            String originalString = ModifiedRequestJsonObject.toString();
            String encryptedString = null;

            try {
                encryptedString = AESCrypt.encrypt(secretkey, originalString, iv);


            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }


            Request compressedRequest = OkHttpRequest.newBuilder()
                    .method(OkHttpRequest.method(), RequestBody.create(OkHttpRequest.body().contentType(), encryptedString))
                    .build();


            return compressedRequest;

        } else {
            return OkHttpRequest;

        }


    }


    public static String bodyToString(final RequestBody request) {
        try {
            final RequestBody copy = request;
            final Buffer buffer = new Buffer();
            if (copy != null)
                copy.writeTo(buffer);
            else
                return "";
            return buffer.readUtf8();
        } catch (final IOException e) {
            return "did not work";
        }
    }


}
