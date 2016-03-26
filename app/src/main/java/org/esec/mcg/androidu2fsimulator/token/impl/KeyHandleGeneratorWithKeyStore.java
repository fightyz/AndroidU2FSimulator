package org.esec.mcg.androidu2fsimulator.token.impl;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.esec.mcg.androidu2fsimulator.token.KeyHandleGenerator;
import org.esec.mcg.androidu2fsimulator.token.U2FTokenActivity;
import org.esec.mcg.androidu2fsimulator.token.U2FTokenException;
import org.esec.mcg.androidu2fsimulator.token.utils.ByteUtil;
import org.esec.mcg.androidu2fsimulator.token.utils.logger.LogUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Created by yz on 2016/1/19.
 */
public class KeyHandleGeneratorWithKeyStore implements KeyHandleGenerator {

    private Cipher mCipher;
    private KeyPair mPair;

    private static void generateKeyPair(Context context, String alias)
            throws GeneralSecurityException {
        final Calendar start = new GregorianCalendar();
        final Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 100);
    }

    /**
     * Wrap a {@link SecretKey} using the public key assigned to this wrapper.
     * Use {@link #unwrap(byte[])} to later recover the original
     * {@link SecretKey}.
     *
     * @return a wrapped version of the given {@link SecretKey} that can be
     *         safely stored on untrusted storage.
     */
    public byte[] wrap(PrivateKey key) throws GeneralSecurityException {
        mCipher.init(Cipher.WRAP_MODE, mPair.getPublic());
        return mCipher.wrap(key);
    }
    /**
     * Unwrap a {@link SecretKey} using the private key assigned to this
     * wrapper.
     *
     * @param blob a wrapped {@link SecretKey} as previously returned by
     *            {@link #wrap(PrivateKey)}.
     */
    public PrivateKey unwrap(byte[] blob) throws GeneralSecurityException {
        mCipher.init(Cipher.UNWRAP_MODE, mPair.getPrivate());
        return (PrivateKey) mCipher.unwrap(blob, "AES", Cipher.PRIVATE_KEY);
    }



    @Override
    public KeyPair generateKeyPair() {
        return null;
    }

    @Override
    public byte[] generateKeyHandle(byte[] applicationSha256, PrivateKey pvk) {
        return new byte[0];
    }

    @Override
    public byte[] generateKeyHandle(byte[] applicationSha256, byte[] challengeSha256) throws U2FTokenException{
        byte[] keyHandle = new byte[applicationSha256.length + challengeSha256.length];
        ByteBuffer.wrap(keyHandle).put(applicationSha256).put(challengeSha256);
        String keyHandleString = Base64.encodeToString(keyHandle, Base64.NO_WRAP | Base64.URL_SAFE).substring(keyHandle.length - 10);
        LogUtils.d("generateKeyHandle key handle: " + ByteUtil.ByteArrayToHexString(keyHandle));
        try {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyStore.containsAlias(keyHandleString)) {
                //TODO throw exception
//                throw new U2FException("Key handle already existed.");
//                keyStore.deleteEntry(keyHandleString);
                new RuntimeException("key handle already existed");
            }

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            keyHandleString,
                            KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .build()
            );
            keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return keyHandle;
    }

    @Override
    public PrivateKey getUserPrivateKey(String keyHandle) throws U2FTokenException {
        return null;
    }

    public PrivateKey getUserPrivateKey(byte[] keyHandle) throws U2FTokenException {

        String keyHandleString = Base64.encodeToString(keyHandle, Base64.NO_WRAP | Base64.URL_SAFE).substring(keyHandle.length - 10);
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyStore.containsAlias(keyHandleString)) {
                LogUtils.d("getUserPrivateKey key handle: " + ByteUtil.ByteArrayToHexString(keyHandle));
                return (PrivateKey)keyStore.getKey(keyHandleString, null);
            } else {
                throw new U2FTokenException(U2FTokenActivity.INVALID_KEY_HANDLE);
            }

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean checkKeyHandle(byte[] keyHandle) throws U2FTokenException {
        LogUtils.d("check key handle: " + ByteUtil.ByteArrayToHexString(keyHandle));
        String keyHandleString = Base64.encodeToString(keyHandle, Base64.NO_WRAP | Base64.URL_SAFE).substring(keyHandle.length - 10);
        final KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyStore.containsAlias(keyHandleString)) {
                return true;
            } else {
                return false;
            }
        } catch (KeyStoreException |CertificateException
                | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            throw new U2FTokenException("Wrong with Key Store.", e);
        }
    }
}
