package com.angelsgate_lite.sdk.AngelsGateNetwork;



import com.angelsgate_lite.sdk.AngelsGateUtils.AESCrypt;
import com.angelsgate_lite.sdk.AngelsGateUtils.AngelGateConstants;
import com.angelsgate_lite.sdk.AngelsGateUtils.Base64Utils;
import com.angelsgate_lite.sdk.AngelsGateUtils.EncodeAlgorithmUtils;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;

/**
 * Created by om on 7/19/2018.
 */

public class DecodeResponse {




    public static String decode(String encryptedString, String Ssalt, String mainDeviceId) {


        JSONObject ModifiedResponseJsonObject = null;
        JSONObject DataResponseJsonObject = new JSONObject();


        String iv = AngelGateConstants.iv;
        String secretkey = AngelGateConstants.secretkey;


        String KeyRotational = EncodeAlgorithmUtils.KeyRotational( Ssalt , secretkey);


        String decryptedString = null;

        try {
            decryptedString = AESCrypt.decrypt(KeyRotational, encryptedString, iv);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }





        try {
            ModifiedResponseJsonObject = new JSONObject(decryptedString);

            String Signature = (String) ModifiedResponseJsonObject.get("Signature");


            int currentYear = Calendar.getInstance().get(Calendar.YEAR);

            String Token = (String) ModifiedResponseJsonObject.get("Token");
            String Md5Deviceid = (String) ModifiedResponseJsonObject.get("Deviceid");
            int Segment = Integer.parseInt(ModifiedResponseJsonObject.get("Segment").toString());





            String ComputedSignature = EncodeAlgorithmUtils.computeHash( Ssalt  + ModifiedResponseJsonObject.get("Data").toString() + currentYear + Segment + mainDeviceId, Token);

            boolean checkedAccepted = checkSecurity(mainDeviceId, Md5Deviceid, ComputedSignature, Signature);

            if (checkedAccepted) {

                return Base64Utils.Base64Decode(ModifiedResponseJsonObject.get("Data").toString());


            } else {

                return "SECURITY_LOCAL_ERROR";
            }




        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return "";
    }


    private static boolean checkSecurity(String mainDeviceId, String Md5Deviceid, String ComputedSignature2, String Signature) {


        try {

            if (!Md5Deviceid.equals(EncodeAlgorithmUtils.md5(mainDeviceId))) {
                return false;
            }

            if (!ComputedSignature2.equals(Signature)) {
                return false;
            }

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }


}