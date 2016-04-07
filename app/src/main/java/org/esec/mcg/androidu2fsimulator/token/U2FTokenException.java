package org.esec.mcg.androidu2fsimulator.token;

/**
 * Created by yz on 2016/3/16.
 */
public class U2FTokenException extends Exception {
//    public U2FTokenException(String message) { super(message); }
//    public U2FTokenException(String message, Throwable cause) { super(message, cause); }
    private final int code;

    public U2FTokenException(int code) {
        super(String.format("Error code: %04x", code));
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
