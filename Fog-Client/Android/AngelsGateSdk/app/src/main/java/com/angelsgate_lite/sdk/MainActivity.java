package com.angelsgate_lite.sdk;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;

import com.angelsgate_lite.sdk.AngelsGateNetwork.EncodeRequestInterceptor;
import com.angelsgate_lite.sdk.AngelsGateNetwork.model.SignalRequest;
import com.angelsgate_lite.sdk.AngelsGateNetwork.model.TestDataRequest;
import com.angelsgate_lite.sdk.AngelsGateUtils.AESCrypt;
import com.angelsgate_lite.sdk.AngelsGateUtils.AngelGateConstants;
import com.angelsgate_lite.sdk.AngelsGateUtils.EncodeAlgorithmUtils;
import com.angelsgate_lite.sdk.AngelsGateUtils.RandomUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import okhttp3.OkHttpClient;
import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

public class MainActivity extends AppCompatActivity {

    ApiInterface apiInterface;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        ////////////////

        Button test_button = (Button) findViewById(R.id.test);
        Button signal_button = (Button) findViewById(R.id.signal);


        final String deviceId = RandomUtils.randomAlphaNumeric(30);


        test_button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                test(deviceId);
            }
        });

        signal_button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    signal(deviceId);
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
        });


        String baseUrl = "";
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .addInterceptor(new EncodeRequestInterceptor(getApplicationContext()))
                .build();


        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl(baseUrl + "/")
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build();


        apiInterface = retrofit.create(ApiInterface.class);


        //////////////

        String iv = "";
        String SecretKey = "";
        String PublicKey ="";


        AngelGateConstants angel = new AngelGateConstants.AngelGateConstantsBuilder(
                PublicKey, iv, SecretKey, baseUrl)
                .setMaxLengthSsalt(14)
                .setMintLengthSsalt(16)
                .build();


        /////////////////
        ////RequestHeader
//        final long segment = AngelsGate.CreatSegment(MainActivity.this);
//        final String Ssalt = AngelsGate.CreatSsalt();
//        final long TimeStamp = AngelsGate.CreatTimeStamp();
//        final String Request = "Test";
//        boolean isArrayRequest = false;
//        final String DeviceId = "123456";


//        TestDataRequest input = new TestDataRequest("HELLO");
//        try {
//            Response<ResponseBody> response = apiInterface.TestApi(TimeStamp, DeviceId, segment, Ssalt, Request, isArrayRequest,input).execute();
//            if (response.isSuccessful()) {
//                String bodyResponse = response.body().string();
//                String data_response = AngelsGate.DecodeResponse(bodyResponse, Ssalt, DeviceId, Request, MainActivity.this);
//                AngelsGate.ErroreHandler(data_response);
//            }
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
//        }


        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        ////RequestHeader
//        final long segment = AngelsGate.CreatSegment(MainActivity.this);
//        final String Ssalt = AngelsGate.CreatSsalt();
//        final long TimeStamp = AngelsGate.CreatTimeStamp();
//        final String Request = "Test";
//        boolean isArrayRequest = false;
//        final String DeviceId = "123456";
//
//
//        OkHttpClient client = new OkHttpClient();
//
//        //add parameters
//        HttpUrl.Builder urlBuilder = HttpUrl.parse("https://www.example.com").newBuilder();
//        urlBuilder.addQueryParameter("query", "example");
//
//
//        String url = urlBuilder.build().toString();
//
//        //build the request
//        Request request = new Request.Builder().url(url).build();
//
//
//        try {
//            request = AngelsGate.EncodeRequest(request, TimeStamp, DeviceId, segment, Ssalt, Request, isArrayRequest, getApplicationContext());
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
//        }
//
//
//        //execute
//        try {
//            okhttp3.Response response2 = client.newCall(request).execute();
//
//            String bodyResponse = response2.body().string();
//            String data_response = AngelsGate.DecodeResponse(bodyResponse, Ssalt, DeviceId, Request, MainActivity.this);
//            AngelsGate.ErroreHandler(data_response);
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
//        }
//

    }


    public void test(String deviceId) {
        ///TestApi
        ////RequestHeader
        final long segment = AngelsGate.CreatSegment(MainActivity.this);
        final String Ssalt = AngelsGate.CreatSsalt();
        final long TimeStamp = AngelsGate.CreatTimeStamp();
        final String Request = "checkUpdate";
        boolean isArrayRequest = false;
        final String DeviceId = deviceId;

        TestDataRequest input = new TestDataRequest("hello");

        Call<ResponseBody> callback3 = apiInterface.TestApi(TimeStamp, DeviceId, segment, Ssalt, Request, isArrayRequest, input);
        callback3.enqueue(new Callback<ResponseBody>() {


            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {


                if (response.isSuccessful()) {

                    String bodyResponse = null;
                    try {
                        bodyResponse = response.body().string();


                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    try {


                        if (AngelsGate.StringErroreHandler(bodyResponse)) {

                            String data_response = AngelsGate.DecodeResponse(bodyResponse, Ssalt, DeviceId, Request, MainActivity.this);



                            AngelsGate.ErroreHandler(data_response);

                        } else {


                        }


                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    }


                } else {

                }
            }

            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {

            }
        });


    }


    public void signal(String deviceId) throws GeneralSecurityException, UnsupportedEncodingException {
        ///signal
        ////RequestHeader
        final long segment = AngelsGate.CreatSegment(MainActivity.this);
        final String Ssalt = AngelsGate.CreatSsalt();
        final long TimeStamp = AngelsGate.CreatTimeStamp();
        final String Request = AngelGateConstants.SignalMethodName;
        boolean isArrayRequest = false;
        final String DeviceId = deviceId;


        SignalRequest input = new SignalRequest(AESCrypt.encrypt(AngelGateConstants.secretkey,"Addition data", AngelGateConstants.iv), EncodeAlgorithmUtils.md5("Token"));



        Call<ResponseBody> callback3 = apiInterface.signal(TimeStamp, DeviceId, segment, Ssalt, Request, isArrayRequest, input);
        callback3.enqueue(new Callback<ResponseBody>() {


            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {

                if (response.isSuccessful()) {


                    String bodyResponse = null;
                    try {
                        bodyResponse = response.body().string();



                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    boolean error = AngelsGate.ErroreHandler(bodyResponse);


                    if (!error) {
                        ///ERROR IN RESPONSE
                    } else {

                        if (Integer.parseInt(bodyResponse) > 0) {

                            //ACTION
                        } else {
                            String SignalError = AngelsGate.SignalErroreHandler(Integer.parseInt(bodyResponse));

                        }

                    }


                } else {


                }
            }

            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {

            }
        });


    }


}
