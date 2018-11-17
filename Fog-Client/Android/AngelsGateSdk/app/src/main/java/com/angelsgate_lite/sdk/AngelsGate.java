package com.angelsgate_lite.sdk;

import android.content.Context;

import com.angelsgate_lite.sdk.AngelsGateNetwork.DecodeResponse;
import com.angelsgate_lite.sdk.AngelsGateNetwork.EncodeRequest;
import com.angelsgate_lite.sdk.AngelsGateUtils.AngelGateErroreHandler;
import com.angelsgate_lite.sdk.AngelsGateUtils.RSACrypt;
import com.angelsgate_lite.sdk.AngelsGateUtils.RandomUtils;
import com.angelsgate_lite.sdk.AngelsGateUtils.prefs.AngelGatePreferencesHelper;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.Timestamp;

import okhttp3.Request;

public class AngelsGate {

    public static String CreatSsalt() {
        return RandomUtils.CreatSsalt();
    }


    public static long CreatSegment(Context ctx) {
        return RandomUtils.CreatSegment(ctx);
    }


    public static long CreatTimeStamp() {
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        long timestampSecond = (timestamp.getTime() / 1000);
        return timestampSecond;
    }


    public static String DecodeResponse(String encryptedString, String Ssalt, String mainDeviceId, String methodName, Context ctx) throws GeneralSecurityException {
        return DecodeResponse.decode(encryptedString, Ssalt, mainDeviceId);
    }


    public static Request EncodeRequest(Request OkHttpRequest, long timestamp, String deviceId, long Segment, String Ssalt, String nameMethode, boolean isArrayResponse, Context ctx) throws UnsupportedEncodingException, GeneralSecurityException {
        return EncodeRequest.EncodeRequest(OkHttpRequest, timestamp, deviceId, Segment, Ssalt, nameMethode, isArrayResponse, ctx);
    }


    public static boolean ErroreHandler(String respose) {
        return AngelGateErroreHandler.ErrorHandler(respose);
    }


    public static boolean StringErroreHandler(String respose) {
        return AngelGateErroreHandler.StringErrorHandler(respose);
    }



    public static String SignalErroreHandler(int respose) {
        return AngelGateErroreHandler.SignalErrorHandler(respose);
    }
}
