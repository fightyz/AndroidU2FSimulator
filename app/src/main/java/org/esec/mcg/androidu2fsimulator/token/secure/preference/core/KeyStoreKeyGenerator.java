package org.esec.mcg.androidu2fsimulator.token.secure.preference.core;

import android.app.Application;
import android.security.KeyChain;
import android.util.Base64;

import org.esec.mcg.androidu2fsimulator.token.secure.preference.vault.SecretKeyWrapper;
import org.esec.mcg.androidu2fsimulator.token.secure.preference.vault.Utils;
import org.spongycastle.jcajce.provider.symmetric.util.PBE;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by yz on 2016/7/13.
 */
public class KeyStoreKeyGenerator implements KeyGenerator {

    public static final String TAG = "KeyGenerator";
    private static final int DATA_KEY_LENGTH = 32;

    private Application application;

    /**
     * Flag indicating that the {@link SecretKeyWrapper} public/private key is
     * hardware-backed. A software keystore is more vulnerable to offline
     * attacks if the device is comprised.
     */
    private boolean isHardwareBacked;

    /**
     * File where wrapped symmetric key is stored.
     */
    private File keyFile;

    private KeyStoreKeyGenerator(Application application, String filename) {
        this.application = application;
        this.isHardwareBacked = KeyChain.isBoundKeyAlgorithm("RSA");
        this.keyFile = new File(application.getFilesDir(), filename);
    }

    public static KeyStoreKeyGenerator get(Application application, String fileName) {
        return new KeyStoreKeyGenerator(application, fileName);
    }

    /**
     * If key is already present then returns it otherwise generates a random key and returns it
     * @return key
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @Override
    public String loadOrGenerateKeys() throws GeneralSecurityException, IOException {
        final SecretKeyWrapper wrapper = new SecretKeyWrapper(application, TAG);
        // Generate secret key if none exists
        if (!keyFile.exists()) {
            final byte[] raw = new byte[DATA_KEY_LENGTH];
            new SecureRandom().nextBytes(raw);
            final SecretKey key = new SecretKeySpec(raw, "AES");
            final byte[] wrapped = wrapper.wrap(key);
            Utils.writeFully(keyFile, wrapped);
        }
        // Even if we just generated the key, always read it back to ensure we
        // can read it successfully.
        final byte[] wrapped = Utils.readFully(keyFile);
        final SecretKey key = wrapper.unwrap(wrapped);
        return Base64.encodeToString(key.getEncoded(), Base64.DEFAULT);
    }

    /**
     * Indicates whether the {@link SecretKeyWrapper} public/private key is
     * hardware-backed. A software keystore is more vulnerable to offline
     * attacks if the device is compromised.
     * @return boolean to know whether key is hardware backed or not
     */
    @Override
    public boolean isHardwareBacked() {
        return isHardwareBacked;
    }
}
