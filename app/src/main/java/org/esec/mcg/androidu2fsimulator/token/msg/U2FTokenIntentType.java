package org.esec.mcg.androidu2fsimulator.token.msg;

/**
 * Created by yz on 2016/3/16.
 * Indicate the intent type when the client call the token.
 * U2F_OPERATION_REG is register operation.
 * U2F_OPERATION_SIGN_BATCH is sign operation.
 */
public enum U2FTokenIntentType {
    U2F_OPERATION_REG,
    U2F_OPERATION_SIGN_BATCH
}
