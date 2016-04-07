package org.esec.mcg.androidu2fsimulator.token;

import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.U2FTokenIntentType;

/**
 * Created by yz on 2016/4/6.
 */
public class TokenTask {
    private OnTokenTaskFinishListener mListener;
    private Enum<U2FTokenIntentType> operation;
    private AuthenticationRequest[] mAuthenticationRequests;
    private RegistrationRequest mRegistrationRequest;

    public static interface OnTokenTaskFinishListener {
        void onTokenTaskSuccess();
        void onTokenTaskFail();
    }
}
