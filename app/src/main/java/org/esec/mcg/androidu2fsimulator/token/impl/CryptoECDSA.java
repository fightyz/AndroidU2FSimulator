package org.esec.mcg.androidu2fsimulator.token.impl;

import org.esec.mcg.androidu2fsimulator.token.Crypto;
import org.esec.mcg.androidu2fsimulator.token.U2FTokenException;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by yz on 2016/1/21.
 */
public class CryptoECDSA implements Crypto {

    static {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
    }

    @Override
    public byte[] sign(byte[] signedData, PrivateKey certificatePrivateKey) throws U2FTokenException {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(certificatePrivateKey);
            signature.update(signedData);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new U2FTokenException("Error when signing", e);
        } catch (SignatureException e) {
            throw new U2FTokenException("Error when signing", e);
        } catch (InvalidKeyException e) {
            throw new U2FTokenException("Error when signing", e);
        }
    }

    public byte[] getPublicKey(byte[] pubKey) {
// Test the public key for sanity
        byte[] publicKey = new byte[65];
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("ECDSA", "SC");
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKey);
            PublicKey pub = kf.generatePublic(pubKeySpec);
            BCECPublicKey pbk = (BCECPublicKey) pub;        // Easier to get Q value from this
            System.arraycopy(pbk.getQ().getEncoded(), 0, publicKey, 0, 65);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }
}
