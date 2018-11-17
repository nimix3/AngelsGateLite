package com.angelsgate_lite.sdk.AngelsGateNetwork.model;

/**
 * Created by om on 8/17/2018.
 */

public class SignalRequest {

    String S;
    String C;

    public SignalRequest(String Addition, String Token) {
        S = Addition;
        this.C = Token;
    }
}
