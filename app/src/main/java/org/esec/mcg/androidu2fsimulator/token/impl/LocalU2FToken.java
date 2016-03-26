package org.esec.mcg.androidu2fsimulator.token.impl;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import org.esec.mcg.androidu2fsimulator.token.Crypto;
import org.esec.mcg.androidu2fsimulator.token.DataStore;
import org.esec.mcg.androidu2fsimulator.token.KeyHandleGenerator;
import org.esec.mcg.androidu2fsimulator.token.KeyPairGenerator;
import org.esec.mcg.androidu2fsimulator.token.U2FToken;
import org.esec.mcg.androidu2fsimulator.token.U2FTokenActivity;
import org.esec.mcg.androidu2fsimulator.token.U2FTokenException;
import org.esec.mcg.androidu2fsimulator.token.UserPresenceVerifier;
import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.RawMessageCodec;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationResponse;
import org.esec.mcg.androidu2fsimulator.token.utils.ByteUtil;
import org.esec.mcg.androidu2fsimulator.token.utils.logger.LogUtils;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by yz on 2016/1/14.
 */
public class LocalU2FToken implements U2FToken {

    private final X509Certificate attestationCertificate;
    private final PrivateKey certificatePrivateKey;
    private final KeyPairGenerator keyPairGenerator;
    private final KeyHandleGenerator keyHandleGenerator;
    private final DataStore dataStore;
    private final UserPresenceVerifier userPresenceVerifier;
    private final Crypto crypto;

    private Context context;

    public LocalU2FToken(Context context) {
        attestationCertificate = (X509Certificate) AttestationCertificate.getAttestationCertificate();
        certificatePrivateKey = AttestationCertificate.getAttestationPrivateKey();
        keyPairGenerator = new SCSecp256r1();

        keyHandleGenerator = new KeyHandleGeneratorWithSC();
        dataStore = null;
        userPresenceVerifier = null;
        crypto = new CryptoECDSA();
        this.context = context;
    }

    @Override
    public RegistrationResponse register(RegistrationRequest registrationRequest) throws U2FTokenException {
        byte[] applicationSha256 = registrationRequest.getApplicationSha256();
        byte[] challengeSha256 = registrationRequest.getChallengeSha256();

        KeyPair kp = keyHandleGenerator.generateKeyPair();
        byte[] keyHandle = keyHandleGenerator.generateKeyHandle(applicationSha256, kp.getPrivate());
        LogUtils.d("keyHanle length: " + keyHandle.length);
        LogUtils.d("keyHandle: " + ByteUtil.ByteArrayToHexString(keyHandle));

        byte[] userPublicKey = crypto.getPublicKey(kp.getPublic().getEncoded());
        LogUtils.d("userPublicKey: " + ByteUtil.ByteArrayToHexString(userPublicKey));
        byte[] signedData = RawMessageCodec.encodeRegistrationSignedBytes(applicationSha256, challengeSha256,
                keyHandle, userPublicKey);

        if (certificatePrivateKey == null) {
        }
        byte[] signature = crypto.sign(signedData, certificatePrivateKey);
        return new RegistrationResponse(userPublicKey, keyHandle, attestationCertificate, signature);
    }


    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) throws U2FTokenException {
        byte[] applicationSha256 = authenticationRequest.getApplicationSha256();
        byte[] challengeSha256 = authenticationRequest.getChallengeSha256();
        byte[] keyHandle = authenticationRequest.getKeyHandle();
        byte control = authenticationRequest.getControl();

        if (control == AuthenticationRequest.USER_PRESENCE_SIGN) {
            LogUtils.d("authenticate key handle: " + ByteUtil.ByteArrayToHexString(keyHandle));
            PrivateKey privateKey = keyHandleGenerator.getUserPrivateKey(Base64.encodeToString(keyHandle, Base64.URL_SAFE));

            // TODO: 2016/3/8 counter should be stored safely
            SharedPreferences sharedPreferences = context.getSharedPreferences("org.esec.mcg.android.fido.PREFERENCE_FILE_KEY"
                    .concat(".").concat(Base64.encodeToString(keyHandle, Base64.NO_WRAP | Base64.URL_SAFE).substring(keyHandle.length - 10)), Context.MODE_PRIVATE);
            int counter = sharedPreferences.getInt("Counter", 1);
            SharedPreferences.Editor editor = sharedPreferences.edit();
            editor.putInt("Counter", counter + 1);
            editor.commit();
            byte[] signedData = RawMessageCodec.encodeAuthenticationSignedBytes(applicationSha256, (byte)0x01, counter, challengeSha256);

            byte[] signature = crypto.sign(signedData, privateKey);
            Log.d("Counter", ""+counter);
            return new AuthenticationResponse((byte)0x01, counter, signature);
        } else if (control == AuthenticationRequest.CHECK_ONLY) {
            boolean keyHandlePresence = keyHandleGenerator.checkKeyHandle(keyHandle);
            if (keyHandlePresence) { // Reg: key handle had been registered
                throw new U2FTokenException(U2FTokenActivity.TEST_OF_PRESENCE_REQUIRED);
            } else { // Reg: not found key handle
                throw new U2FTokenException(U2FTokenActivity.INVALID_KEY_HANDLE);
            }
        } else {
            throw new U2FTokenException("unsupported control byte");
        }

    }
}
