package com.angelsgate_lite.sdk.AngelsGateUtils.prefs;

import android.content.Context;
import android.content.SharedPreferences;

import com.angelsgate_lite.sdk.AngelsGateUtils.AngelGateConstants;
import com.angelsgate_lite.sdk.AngelsGateUtils.RandomUtils;

public class AngelGatePreferencesHelper {

    private static final String PREF_KEY_SEGMENT = "PREF_KEY_SEGMENT";
    private static final String PREF_KEY_HANDLER = "PREF_KEY_HANDLER";


    public static void ResetAllData(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);

        mPrefs.edit().putLong(PREF_KEY_SEGMENT, 0).apply();
        mPrefs.edit().putString(PREF_KEY_HANDLER, RandomUtils.randomAlphaNumeric(20)).apply();

    }



    public static long getSegment(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        return mPrefs.getLong(PREF_KEY_SEGMENT, 0);
    }


    public static void setSegment(long segment, Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putLong(PREF_KEY_SEGMENT, segment).apply();
    }




///////////////////////////////////////
    public static String getHandler(Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        return mPrefs.getString(PREF_KEY_HANDLER, RandomUtils.randomAlphaNumeric(20));
    }


    public static void setHandler(String handler, Context context) {
        SharedPreferences mPrefs = context.getSharedPreferences("AngelGatePrefs", Context.MODE_PRIVATE);
        mPrefs.edit().putString(PREF_KEY_HANDLER, handler).apply();
    }


}
