package org.esec.mcg.androidu2fsimulator.token.msg;

/**
 * Created by yz on 2016/4/7.
 */
public class ErrorResponse implements BaseResponse {
    private final int errorCode;

    public ErrorResponse(int errorCode) {
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
