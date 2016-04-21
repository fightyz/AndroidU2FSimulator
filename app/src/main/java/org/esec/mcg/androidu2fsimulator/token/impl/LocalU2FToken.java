package org.esec.mcg.androidu2fsimulator.token.impl;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import org.esec.mcg.androidu2fsimulator.token.Crypto;
import org.esec.mcg.androidu2fsimulator.token.KeyHandleGenerator;
import org.esec.mcg.androidu2fsimulator.token.U2FToken;
import org.esec.mcg.androidu2fsimulator.token.U2FTokenActivity;
import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.BaseResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.ErrorResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.RawMessageCodec;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationResponse;
import org.esec.mcg.androidu2fsimulator.token.utils.ByteUtil;
import org.esec.mcg.androidu2fsimulator.token.utils.logger.LogUtils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Created by yz on 2016/1/14.
 */
public class LocalU2FToken implements U2FToken {

    private final X509Certificate attestationCertificate;
    private final PrivateKey certificatePrivateKey;
    private final KeyHandleGenerator keyHandleGenerator;
    private final Crypto crypto;

    private Context context;

    public LocalU2FToken(Context context) {
        attestationCertificate = (X509Certificate) AttestationCertificate.getAttestationCertificate();
        certificatePrivateKey = AttestationCertificate.getAttestationPrivateKey();

        keyHandleGenerator = new KeyHandleGeneratorWithSC();
        crypto = new CryptoECDSA();
        this.context = context;
    }

    @Override
    public BaseResponse register(RegistrationRequest registrationRequest) {
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
    public BaseResponse authenticate(AuthenticationRequest authenticationRequest) {
        byte[] applicationSha256 = authenticationRequest.getApplicationSha256();
        byte[] challengeSha256 = authenticationRequest.getChallengeSha256();
        byte[] keyHandle = authenticationRequest.getKeyHandle();
        byte control = authenticationRequest.getControl();

        if (control == AuthenticationRequest.USER_PRESENCE_SIGN) {
            LogUtils.d("authenticate key handle: " + ByteUtil.ByteArrayToHexString(keyHandle));
            PrivateKey privateKey = keyHandleGenerator.getUserPrivateKey(Base64.encodeToString(keyHandle, Base64.URL_SAFE));
            if (privateKey == null) {
//                throw new U2FTokenException(U2FTokenActivity.SW_INVALID_KEY_HANDLE);
                return new ErrorResponse(U2FTokenActivity.SW_INVALID_KEY_HANDLE);
            }
            LogUtils.d("privateKey: " + ByteUtil.ByteArrayToHexString(privateKey.getEncoded()));
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
            PrivateKey prk = keyHandleGenerator.getUserPrivateKey(Base64.encodeToString(keyHandle, Base64.URL_SAFE));
            if (prk != null) { // Reg: key handle had been registered
//                throw new U2FTokenException(U2FTokenActivity.SW_TEST_OF_PRESENCE_REQUIRED);
                return new ErrorResponse(U2FTokenActivity.SW_TEST_OF_PRESENCE_REQUIRED);
            } else { // Reg: not found key handle
//                throw new U2FTokenException(U2FTokenActivity.SW_INVALID_KEY_HANDLE);
                return new ErrorResponse(U2FTokenActivity.SW_INVALID_KEY_HANDLE);
            }
        } else {
//            throw new U2FTokenException("unsupported control byte");
            throw new RuntimeException("This should not happed.");
        }
    }
}
