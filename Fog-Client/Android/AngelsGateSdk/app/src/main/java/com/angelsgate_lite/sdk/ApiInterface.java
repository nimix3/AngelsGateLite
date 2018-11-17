package com.angelsgate_lite.sdk;


import com.angelsgate_lite.sdk.AngelsGateNetwork.model.SignalRequest;
import com.angelsgate_lite.sdk.AngelsGateNetwork.model.TestDataRequest;

import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.Header;
import retrofit2.http.POST;

/**
 * Created by om on 10/22/2017.
 */

public interface ApiInterface {


    @POST("App2.php")
    Call<ResponseBody> TestApi(@Header("Timestamp") long timestamp, @Header("DeviceId") String deviceId, @Header("Segment") long segment, @Header("Ssalt") String Ssalt, @Header("Request") String nameMethode, @Header("isArrayResponse") boolean isArrayResponse, @Body TestDataRequest input);


    @POST("Signal2.php")
    Call<ResponseBody> signal(@Header("Timestamp") long timestamp, @Header("DeviceId") String deviceId, @Header("Segment") long segment, @Header("Ssalt") String Ssalt, @Header("Request") String nameMethode, @Header("isArrayResponse") boolean isArrayResponse,  @Body SignalRequest input);



}
