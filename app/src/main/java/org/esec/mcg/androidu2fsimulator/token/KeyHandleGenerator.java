package org.esec.mcg.androidu2fsimulator.token;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;

/**
 * Created by yz on 2016/1/18.
 */
public interface KeyHandleGenerator {
    KeyPair generateKeyPair();
    byte[] generateKeyHandle(byte[] applicationSha256, PrivateKey pvk);
    byte[] generateKeyHandle(byte[] applicationSha256, byte[] challengeSha256);
    PrivateKey getUserPrivateKey(String keyHandle);
    boolean checkKeyHandle(byte[] keyHandle) throws U2FTokenException;
}
