package org.esec.mcg.androidu2fsimulator.token.impl;

import org.esec.mcg.androidu2fsimulator.token.KeyHandleGenerator;
import org.esec.mcg.androidu2fsimulator.token.U2FTokenException;
import org.esec.mcg.androidu2fsimulator.token.utils.ByteUtil;
import org.esec.mcg.androidu2fsimulator.token.utils.logger.LogUtils;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jce.provider.BouncyCastleProvider;

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
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

/**
 * Created by yz on 2016/3/23.
 */
public class KeyHandleGeneratorWithSC implements KeyHandleGenerator {

    static {
        // Add SpongyCastle JCE provider
        if (Security.getProvider("SC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    @Override
    public byte[] generateKeyHandle(byte[] applicationSha256, KeyPair keyPair) {
        return new byte[0];
    }

    @Override
    public byte[] generateKeyHandle(byte[] applicationSha256, byte[] challengeSha256) throws U2FTokenException {
        try {
            KeyPair userKeyPair = generateKeyPair();
            byte[] userPrivateKey = ((BCECPrivateKey)userKeyPair.getPrivate()).getS().toByteArray();
            LogUtils.d(ByteUtil.ByteArrayToHexString(userPrivateKey));
            byte[] keyHandle = new byte[userPrivateKey.length + applicationSha256.length + 2];
            keyHandle[0] = (byte)keyHandle.length;
            System.arraycopy(userPrivateKey, 0, keyHandle, 1, userPrivateKey.length);
            System.arraycopy(applicationSha256, 0, keyHandle, 1 + userPrivateKey.length, applicationSha256.length);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public PrivateKey getUserPrivateKey(byte[] keyHandle) throws U2FTokenException {
        return null;
    }

    @Override
    public boolean checkKeyHandle(byte[] keyHandle) throws U2FTokenException {
        return true;
    }

    private static KeyPair generateKeyPair() throws
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            SignatureException {
        ECGenParameterSpec paramSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "SC");
        kpg.initialize(paramSpec, new SecureRandom());
        return kpg.generateKeyPair();
    }
}
