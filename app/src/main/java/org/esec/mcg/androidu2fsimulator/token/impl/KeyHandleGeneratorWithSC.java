package org.esec.mcg.androidu2fsimulator.token.impl;

import android.util.Base64;

import org.esec.mcg.androidu2fsimulator.token.KeyHandleGenerator;
import org.esec.mcg.androidu2fsimulator.token.U2FToken;
import org.esec.mcg.androidu2fsimulator.token.U2FTokenActivity;
import org.esec.mcg.androidu2fsimulator.token.U2FTokenException;
import org.esec.mcg.androidu2fsimulator.token.utils.ByteUtil;
import org.esec.mcg.androidu2fsimulator.token.utils.CharUtil;
import org.esec.mcg.androidu2fsimulator.token.utils.logger.LogUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jcajce.provider.asymmetric.ec.EC5Util;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECPrivateKeySpec;
import org.spongycastle.math.ec.ECCurve;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by yz on 2016/3/23.
 */
public class KeyHandleGeneratorWithSC implements KeyHandleGenerator {
    public static final String FIXED_AES256_WRAPPING_KEY = "0123456789ABCDEF0123456789ABCDEF";

    // Constants related to sizes
    public static final int APPLICATION_PARAMETER_LENGTH = 32;
    public static final int AUTHENTICATOR_COUNTER_LENGTH = 4;
    public static final int AUTHENTICATOR_KEY_HANDLE_LENGTH = 1;
    public static final int CHALLENGE_PARAMETER_LENGTH = 32;
    public static final int ECDSA_P256_PUBLICKEY_LENGTH = 65;
    public static final int ENCRYPTION_MODE_CBC_IV_LENGTH = 16;

    static {
        // Add SpongyCastle JCE provider
        if (Security.getProvider("SC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    public KeyPair generateKeyPair() {
        try {
            ECGenParameterSpec paramSpec = new ECGenParameterSpec("secp256r1");
            KeyPairGenerator kpg = null;
            kpg = KeyPairGenerator.getInstance("ECDSA", "SC");
            kpg.initialize(paramSpec, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] generateKeyHandle(byte[] applicationSha256, PrivateKey pvk) {
        try {
            String originHash = getDigest(applicationSha256, "SHA256");
            // Get wrapping key
            byte[] Seckeybytes = CharUtil.decodeHex(FIXED_AES256_WRAPPING_KEY.toCharArray());
            SecretKeySpec sks = new SecretKeySpec(Seckeybytes, "AES");

            // Extract the private-key component S from the curve
            BCECPrivateKey prk = (BCECPrivateKey) pvk;
            byte[] privateKey = prk.getS().toByteArray();

            // Encode plaintext key-handle into JSON structure
            String ptkh = encodeKeyHandle(Base64.encodeToString(privateKey, Base64.URL_SAFE), originHash, getDigest(pvk.getEncoded(), "SHA1"));
            System.out.println("PlaintextKeyHandle:     " + ptkh);

            // Encrypt key handle to create ciphertext
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "SC");
            cipher.init(Cipher.ENCRYPT_MODE, sks, new SecureRandom());
            byte[] ctkh = cipher.doFinal(ptkh.getBytes("UTF-8"));

            // Recover IV from cipher and prepend to encrypted keyhandle in new array
            byte[] iv = cipher.getIV();
            byte[] ctkhiv = new byte[ctkh.length + ENCRYPTION_MODE_CBC_IV_LENGTH];
            System.arraycopy(iv, 0, ctkhiv, 0, ENCRYPTION_MODE_CBC_IV_LENGTH);              // Copy IV to new array
            System.arraycopy(ctkh, 0, ctkhiv, ENCRYPTION_MODE_CBC_IV_LENGTH, ctkh.length);  // Append ciphertext KH to IV

            // Base64-encode ciphertext keyhandle + IV
            String ctkhivb64 = Base64.encodeToString(ctkhiv, Base64.URL_SAFE);

            // Test recovery of plaintext key-handle before returning
            String ptkh2 = decryptKeyHandle(ctkhivb64);
            if (!ptkh2.trim().equalsIgnoreCase(ptkh.trim())) {
                System.err.println("Decryption of keyhandle failed during test");
                return null;
            }

            return ctkhiv;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (ShortBufferException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }


        return new byte[0];
    }

    @Override
    public byte[] generateKeyHandle(byte[] applicationSha256, byte[] challengeSha256) throws U2FTokenException {
        return new byte[0];
    }

    @Override
    public PrivateKey getUserPrivateKey(String keyHandle) throws U2FTokenException {

        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyFactory kf = null;
        try {
            String khjson = decryptKeyHandle(keyHandle);
            System.out.println("PlaintextKeyHandle:   " + khjson);
            String pvk = decodeKeyHandle(khjson, 0);
            kf = KeyFactory.getInstance("ECDSA", "SC");
            ECCurve curve = params.getCurve();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
            ECParameterSpec paramspec = EC5Util.convertSpec(ellipticCurve, params);
            java.security.spec.ECPrivateKeySpec keyspec = new java.security.spec.ECPrivateKeySpec(new BigInteger(Base64.decode(pvk, Base64.URL_SAFE)), paramspec);
            return kf.generatePrivate(keyspec);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchProviderException e) {
            return null;
        } catch (SignatureException e) {
            return null;
        } catch (ShortBufferException e) {
            return null;
        } catch (InvalidKeySpecException e) {
            return null;
        } catch (UnsupportedEncodingException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        } catch (InvalidKeyException e) {
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            return null;
        } catch (NoSuchPaddingException e) {
            return null;
        } catch (IllegalBlockSizeException e) {
            return null;
        }

    }

    @Override
    public boolean checkKeyHandle(byte[] keyHandle) throws U2FTokenException {
        return true;
    }

    /**
     * Function to encode a keyHandle as a JSON object
     *
     * @param pvk      String containing the Base64-encoded private-key
     * @param origin   String containing the origin with which the key is associated
     * @param sha1hash String containing the SHA1 digest of the key
     * @return String containing the JSON of the keyHandle
     */
    public static String encodeKeyHandle(String pvk, String origin, String sha1hash)
    {
        try {
            return new JSONObject()
                    .put("key", pvk)
                    .put("sha1", sha1hash)
                    .put("origin_hash", origin)
                    .toString();
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Function to decode the return-values of a keyHandle
     *
     * @param input String JSON containing key-values of a decrypted key-handle
     * @param type int specifying the requested value
     * @return String containing the value
     */
    public static String decodeKeyHandle(String input, int type)
    {
        try {
            JSONObject jsonObject = (JSONObject) new JSONTokener(input).nextValue();
            switch (type) {
                case 0:
                    return jsonObject.getString("key");
                case 1:
                    return jsonObject.getString("sha1");
                default:
                    return jsonObject.getString("origin_hash");
            }
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Function to decrypt a private-key and return it from a Base64-encoded
     * key-handle (which has a 16-byte IV prepended to it)
     *
     * @param s String containing a 16-byte IV plus the encrypted keyhandle
     * @return String containing the Base64-encoded plaintext JSON structure
     * of the key-handle
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws ShortBufferException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     */
    public static String decryptKeyHandle(String s)
            throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            ShortBufferException,
            IllegalBlockSizeException,
            BadPaddingException,
            UnsupportedEncodingException,
            InvalidKeySpecException,
            SignatureException
    {
        // Get wrapping key
        byte[] Seckeybytes = CharUtil.decodeHex(FIXED_AES256_WRAPPING_KEY.toCharArray());
        SecretKeySpec sks = new SecretKeySpec(Seckeybytes, "AES");

        // Decode IV + ciphertext and extract components into new arrays
        byte[] ctkhiv = Base64.decode(s, Base64.URL_SAFE);
        byte[] iv = new byte[16];
        byte[] ctkh = new byte[ctkhiv.length - iv.length];
        System.arraycopy(ctkhiv, 0, iv, 0, ENCRYPTION_MODE_CBC_IV_LENGTH);
        System.arraycopy(ctkhiv, ENCRYPTION_MODE_CBC_IV_LENGTH, ctkh, 0, ctkh.length);

        // Decrypt keyhandle using IV in input string
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "SC");
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, sks, ivspec);
        byte[] ptkh = new byte[cipher.getOutputSize(ctkh.length)];
        int p = cipher.update(ctkh, 0, ctkh.length, ptkh, 0);
        cipher.doFinal(ptkh, p);

        // Exctract ECDSA private-key from plaintext JSON keyhandle
        String pvks = decodeKeyHandle(new String(ptkh, "UTF-8"), 0); // 0 for key
        byte[] pvkb = Base64.decode(pvks, Base64.URL_SAFE);

        // Create private key for sanity-check
        ECPrivateKeySpec ecpks = new ECPrivateKeySpec(new BigInteger(pvkb), null);
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "SC");
        PrivateKey pvk = kf.generatePrivate(ecpks);

        // If we don't thrown an exception at this point, we can return JSON
        return new String(ptkh, "UTF-8");
    }

    /**
     * Returns message digest of a byte-array of the specified algorithm
     *
     * @param input     byte[] containing content that must be digested (hashed)
     * @param algorithm String indicating digest algorithm
     * @return String Base64-encoded digest of specified input
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws UnsupportedEncodingException
     */
    public static String getDigest(byte[] input, String algorithm)
            throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            UnsupportedEncodingException
    {
        MessageDigest digest = MessageDigest.getInstance(algorithm, "SC");
        byte[] digestbytes = digest.digest(input);
        return Base64.encodeToString(digestbytes, Base64.URL_SAFE);
    }
}
