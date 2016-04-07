package org.esec.mcg.androidu2fsimulator.token;

import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.ErrorResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationResponse;

/**
 * Created by yz on 2016/4/7.
 */
public interface ResponseHandlerInterface {
    void sendStartMessage();
    void onCheckOnlyFinish();
    void onRegisterFinish(RegistrationResponse response);
    void onAuthenticateFinish(AuthenticationResponse response, int index);
    void onAuthenticateFail();
    void sendCancelMessage();
}
