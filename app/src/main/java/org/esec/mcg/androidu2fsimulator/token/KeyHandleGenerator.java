package org.esec.mcg.androidu2fsimulator.token;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

/**
 * Created by yz on 2016/1/18.
 */
public abstract class KeyHandleGenerator {
    public KeyPair generateKeyPair() {
        try {
            ECGenParameterSpec paramSpec = new ECGenParameterSpec("secp256r1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "SC");
            kpg.initialize(paramSpec, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public abstract byte[] generateKeyHandle(byte[] applicationSha256, PrivateKey pvk);
    public abstract PrivateKey getUserPrivateKey(String keyHandle);
}
