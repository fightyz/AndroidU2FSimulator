package org.esec.mcg.androidu2fsimulator.token;

import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.BaseResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.ErrorResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.U2FTokenIntentType;
import org.esec.mcg.androidu2fsimulator.token.utils.logger.LogUtils;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Created by yz on 2016/4/7.
 */
public class TokenMessageRequest implements Runnable{

    private final AtomicBoolean isCancelled = new AtomicBoolean();
    private final U2FTokenIntentType u2fTokenIntentType;
    private final AuthenticationRequest[] authenticationRequests;
    private final RegistrationRequest registrationRequest;
    private U2FToken u2fToken;
    private final ResponseHandlerInterface responseHandler;
    private volatile boolean isFinished;
    private boolean cancelIsNotified;
    private int authenticationRequestsIndex;

    public TokenMessageRequest(RegistrationRequest registrationRequest,
                               AuthenticationRequest[] authenticationRequests,
                               U2FTokenIntentType u2fTokenIntentType,
                               U2FToken u2fToken,
                               ResponseHandlerInterface responseHandler) {
        this.registrationRequest = registrationRequest;
        this.authenticationRequests = authenticationRequests;
        this.u2fTokenIntentType = u2fTokenIntentType;
        this.u2fToken = u2fToken;
        this.responseHandler = responseHandler;
    }

    @Override
    public void run() {
        if (isCancelled()) {
            return;
        }

        responseHandler.sendStartMessage();

        if (isCancelled()) {
            return;
        }

        doTask();
    }

    private void doTask() {
        switch (u2fTokenIntentType) {
            case U2F_OPERATION_REG:
                register();
                break;
            case U2F_OPERATION_SIGN_BATCH:
                sign();
                break;
            default:
                break;
        }
    }

    private void register() {
        if (authenticationRequests != null) {
            for (int index = 0; index < authenticationRequests.length; index++) {
                ErrorResponse response = (ErrorResponse)u2fToken.authenticate(authenticationRequests[index]);
                if (response.getErrorCode() == U2FTokenActivity.SW_INVALID_KEY_HANDLE) {
                    if (isCancelled()) {
                        return;
                    }
                    continue;
                }
                else if (response.getErrorCode() == U2FTokenActivity.SW_TEST_OF_PRESENCE_REQUIRED) { // Token already has been registered
                    responseHandler.onCheckOnlyFinish();
                    return;
                }
            }
        }

        RegistrationResponse response = (RegistrationResponse)u2fToken.register(registrationRequest);

        if (isCancelled()) {
            return;
        }
        responseHandler.onRegisterFinish(response);
        isFinished = true;
    }

    private void sign() {
        for (int index = 0; index < authenticationRequests.length; index++) {
            BaseResponse response = u2fToken.authenticate(authenticationRequests[index]);
            if (response instanceof ErrorResponse) {
                ErrorResponse _response = (ErrorResponse)response;
                if (_response.getErrorCode() == U2FTokenActivity.SW_INVALID_KEY_HANDLE) {
                    if (isCancelled()) {
                        return;
                    }
                    continue;
                }
            } else if (response instanceof AuthenticationResponse) {
                AuthenticationResponse _response = (AuthenticationResponse)response;
                responseHandler.onAuthenticateFinish(_response, index);
                return;
            }
        }

        responseHandler.onAuthenticateFail();
        isFinished = true;
    }

    public boolean isCancelled() {
        boolean cancelled = isCancelled.get();
        if (cancelled) {
            // TODO: 2016/4/7 handler.sendCancelMessage()
            sendCancelNotification();
            u2fToken = null;
        }
        return cancelled;
    }

    private synchronized void sendCancelNotification() {
        if (!isFinished && isCancelled.get() && !cancelIsNotified) {
            cancelIsNotified = true;
            responseHandler.sendCancelMessage();
        }
    }

    public boolean isDone() {
        return isCancelled() || isFinished;
    }

    public boolean cancel(boolean mayInteruptIfRunning) {
        isCancelled.set(true);
        return isCancelled();
    }
}
