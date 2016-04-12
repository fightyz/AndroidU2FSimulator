package org.esec.mcg.androidu2fsimulator.token.msg;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Created by yz on 2016/3/16.
 */
public class RawMessageCodec {
    public static final byte REGISTRATION_RESERVED_BYTE_VALUE = 0x05;
    public static final byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = 0x00;

    public static byte[] encodeRegistrationSignedBytes(byte[] applicationSha256,
                                                       byte[] challengeSha256,
                                                       byte[] keyHandle,
                                                       byte[] userPublicKey) {
        byte[] signedData = new byte[1 + applicationSha256.length + challengeSha256.length
                + keyHandle.length + userPublicKey.length];
        ByteBuffer.wrap(signedData)
                .put(REGISTRATION_SIGNED_RESERVED_BYTE_VALUE)
                .put(applicationSha256)
                .put(challengeSha256)
                .put(keyHandle)
                .put(userPublicKey);
        return signedData;
    }

    public static byte[] encodeAuthenticationSignedBytes(byte[] applicationSha256,
                                                         byte userPresence,
                                                         int counter,
                                                         byte[] challengeSha256) {
        byte[] signedData = new byte[applicationSha256.length + 1 + 4 + challengeSha256.length];
        byte[] rawCounter = ByteBuffer.allocate(4).putInt(counter).array();

        int cur = 0;
        System.arraycopy(applicationSha256, 0, signedData, cur, applicationSha256.length);
        cur += applicationSha256.length;

        signedData[cur++] = userPresence;

        System.arraycopy(rawCounter, 0, signedData, cur, 4);
        cur += 4;

        System.arraycopy(challengeSha256, 0, signedData, cur, challengeSha256.length);

        return signedData;
    }

    public static byte[] encodeRegistrationResponse(RegistrationResponse registrationResponse) {
        byte[] userPublicKey = registrationResponse.getUserPublicKey();
        byte[] keyHandle = registrationResponse.getKeyHandle();
        X509Certificate attestationCertificate = registrationResponse.getAttestationCertificate();
        byte[] signature = registrationResponse.getSignature();

        byte[] attestationCertificateBytes;
        try {
            attestationCertificateBytes = attestationCertificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        if (keyHandle.length > 255) {
            throw new RuntimeException("keyHandle length cannot be longer than 255 bytes!");
        }

        byte[] result = new byte[1 + userPublicKey.length + 1 + keyHandle.length
                + attestationCertificateBytes.length + signature.length];
        ByteBuffer.wrap(result)
                .put(REGISTRATION_RESERVED_BYTE_VALUE)
                .put(userPublicKey)
                .put((byte) keyHandle.length)
                .put(keyHandle)
                .put(attestationCertificateBytes)
                .put(signature);
        return result;
    }

    public static byte[] encodeAuthenticationResponse(AuthenticationResponse authenticationResponse) {
        byte userPresence = authenticationResponse.getUserPresence();
        int counter = authenticationResponse.getCounter();
        byte[] signature = authenticationResponse.getSignature();
        byte[] rawCounter = ByteBuffer.allocate(4).putInt(counter).array();

        byte[] result = new byte[1 + 4 + signature.length];
        ByteBuffer.wrap(result)
                .put(userPresence)
                .put(rawCounter)
                .put(signature);
        return result;
    }
}
