package org.esec.mcg.androidu2fsimulator.token.impl;

import android.util.Base64;
import android.util.Log;

import org.esec.mcg.androidu2fsimulator.token.KeyHandleGenerator;
import org.esec.mcg.androidu2fsimulator.token.utils.ByteUtil;
import org.esec.mcg.androidu2fsimulator.token.utils.logger.LogUtils;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jcajce.provider.asymmetric.ec.EC5Util;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.math.ec.ECCurve;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Created by yz on 2016/4/21.
 */
public class KeyHandleGeneratorWithSC extends KeyHandleGenerator {
    static {
        // Add SponcyCastle JCE Provider
        if (Security.getProvider("SC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        System.loadLibrary("TWBDES");
    }

    @Override
    public byte[] generateKeyHandle(byte[] applicationSha256, PrivateKey pvk) {
        // Extract the private-key component S from the curve
        BCECPrivateKey prk = (BCECPrivateKey) pvk;
        byte[] privateKey = prk.getS().toByteArray();

        byte[] rawKeyHandle = new byte[applicationSha256.length + privateKey.length];
        ByteBuffer.wrap(rawKeyHandle)
                .put(applicationSha256)
                .put(privateKey);

        return encryptKeyHandle(rawKeyHandle);
    }

    @Override
    public PrivateKey getUserPrivateKey(String keyHandleBase64) {
        try {
            byte[] paddingKeyHandle = Base64.decode(keyHandleBase64, Base64.URL_SAFE);

            byte[] rawKeyHandle = decryptKeyHandle(paddingKeyHandle);
            byte[] privateKey = Arrays.copyOfRange(rawKeyHandle, 32, rawKeyHandle.length);

            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
            KeyFactory kf = KeyFactory.getInstance("ECDSA", "SC");
            ECCurve curve = params.getCurve();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
            ECParameterSpec paramspec = EC5Util.convertSpec(ellipticCurve, params);
            ECPrivateKeySpec keyspec = new ECPrivateKeySpec(new BigInteger(privateKey), paramspec);
            return kf.generatePrivate(keyspec);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchProviderException e) {
            return null;
        } catch (InvalidKeySpecException e) {
            return null;
        }
    }

    private static byte[] paddingWithPKCS5(byte[] data) {
        int mod = data.length % 8;
        int remaining = 8 - mod;
        LogUtils.d(ByteUtil.ByteArrayToHexString(data));
        LogUtils.d("remaining = " + remaining);
        byte[] result = new byte[data.length + remaining];
        System.arraycopy(data, 0, result, 0, data.length);
        Arrays.fill(result, data.length, result.length, (byte)remaining);
        return result;
    }

    private static byte[] unpaddingWithPKCS5(byte[] data) {
        int remaining = data[data.length - 1];
        LogUtils.d(ByteUtil.ByteArrayToHexString(data));
        LogUtils.d("remaining = " + remaining);
        byte[] result = new byte[data.length - remaining];
        System.arraycopy(data, 0, result, 0, data.length - remaining);
        return result;
    }

    private static byte[] encryptKeyHandle(byte[] rawKeyHandle) {
        byte[] paddingKeyHandle = paddingWithPKCS5(rawKeyHandle);


        byte[] result = new byte[paddingKeyHandle.length];
        byte[] block = new byte[8];
        byte[] scratch = new byte[8];
        ByteBuffer byteBuffer = ByteBuffer.wrap(result);
        for (int i = 0; i < result.length; i += 8) {

            System.arraycopy(paddingKeyHandle, i, block, 0, 8);
            System.arraycopy(TDESEncryptBlock(block, true), 0, scratch, 0, 8);
            byteBuffer.put(scratch);
        }
        return result;
    }

    private static byte[] decryptKeyHandle(byte[] keyHandle) {
        byte[] result = new byte[keyHandle.length];
        byte[] block = new byte[8];
        byte[] scratch = new byte[8];
        ByteBuffer byteBuffer = ByteBuffer.wrap(result);
        for (int i = 0; i < result.length; i += 8) {
            System.arraycopy(keyHandle, i, block, 0, 8);
            System.arraycopy(TDESEncryptBlock(block, false), 0, scratch, 0, 8);
            byteBuffer.put(scratch);
        }

        return unpaddingWithPKCS5(result);
    }

    public static native byte[] TDESEncryptBlock(byte[] in,boolean isEncript);
}
