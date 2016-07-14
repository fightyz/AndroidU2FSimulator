package org.esec.mcg.androidu2fsimulator.token.secure.preference.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.provider.Settings;
import android.support.annotation.Nullable;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Created by yz on 2016/7/13.
 * Warning, this gives a false sense of security.  If an attacker has enough access to
 * acquire your password store, then he almost certainly has enough access to acquire your
 * source binary and figure out your encryption key.  However, it will prevent casual
 * investigators from acquiring passwords, and thereby may prevent undesired negative
 * publicity.
 *
 * Main idea by Mike Burton in an answer posted here
 * http://stackoverflow.com/questions/785973/what-is-the-most-appropriate-way-to-store-user-settings-in-android
 * -application
 */
public class ObscuredSharedPreferences implements SharedPreferences {

    protected static final String UTF8 = "utf-8";

    /**
     * The encryption key. This should never be in the source code.
     */
    private static char[] newSecret;

    /**
     * Boolean to indicate whether keys need to encrypted.
     */
    private final boolean encryptKeys;
    private SharedPreferences delegate;
    private Context context;

    public ObscuredSharedPreferences(Context context, SharedPreferences delegate) {
        this.delegate = delegate;
        this.context = context;
        this.encryptKeys = true; // by-default always encrypt keys
    }

    public ObscuredSharedPreferences(Context context, SharedPreferences delegate, boolean encryptKeys) {
        this.delegate = delegate;
        this.context = context;
        this.encryptKeys = encryptKeys;
    }

    private char[] getSecret() throws IllegalAccessException {
        if (newSecret == null) {
            throw new IllegalAccessException("Please add a key");
        } else {
            return newSecret;
        }
    }

    public void setSecret(String secret) {
        newSecret = secret.toCharArray();
    }

    private Set<String> encryptSet(Set<String> values) {
        Set<String> encryptedValues = new HashSet<>();
        for (String value : values) {
            encryptedValues.add(encrypt(value));
        }
        return encryptedValues;
    }

    private Set<String> decryptSet(Set<String> values) {
        Set<String> decryptedValues = new HashSet<>();
        for (String value : values) {
            decryptedValues.add(decrypt(value));
        }
        return decryptedValues;
    }

    protected String encrypt(String value) {
        try {
            final byte[] bytes = value != null ? value.getBytes(UTF8) : new byte[0];
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey key = keyFactory.generateSecret(new PBEKeySpec(getSecret()));
            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
            pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(getSalt(), 20));
            return new String(Base64.encode(pbeCipher.doFinal(bytes), Base64.NO_WRAP), UTF8);

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    protected String decrypt(String value) {
        try {
            final byte[] bytes = value != null ? Base64.decode(value, Base64.NO_WRAP) : new byte[0];
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey key = keyFactory.generateSecret(new PBEKeySpec(getSecret()));
            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
            pbeCipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(getSalt(), 20));
            return new String(pbeCipher.doFinal(bytes), UTF8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    private byte[] getSalt() throws UnsupportedEncodingException {
        String id = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);

        if (id == null) {
            id = "ROBOLECTRICYOUAREBAD";
        }

        byte[] salt = Arrays.copyOf(id.getBytes(UTF8), 8);
        return salt;
    }

    /**
     * returns a map of all the unencrypted key, value pairs
     * @return
     */
    @Override
    public Map<String, String> getAll() {
        Map<String, ?> all = delegate.getAll();
        Set<String> keys = all.keySet();
        HashMap<String, String> unencryptedMap = new HashMap<>(keys.size());
        for (String key : keys) {
            String decryptedKey = decryptKey(key);
            Object value = all.get(key);
            if (value != null) {
                unencryptedMap.put(decryptedKey, decrypt(value.toString()));
            }
        }
        return unencryptedMap;
    }

    private String decryptKey(String key) {
        if (encryptKeys) {
            return decrypt(key);
        }
        return key;
    }

    private String encryptKey(String key) {
        return encryptKeys ? encrypt(key) : key;
    }

    @Nullable
    @Override
    public String getString(String key, String defValue) {
        final String v = delegate.getString(encryptKey(key), null);
        return v != null ? decrypt(v) : defValue;
    }

    @Nullable
    @Override
    public Set<String> getStringSet(String key, Set<String> defValues) {
        final Set<String> stringSet = delegate.getStringSet(encryptKey(key), defValues);
        return stringSet != null ? decryptSet(stringSet) : defValues;
    }

    @Override
    public int getInt(String key, int defValue) {
        final String v = delegate.getString(encryptKey(key), null);
        return v != null ? Integer.parseInt(decrypt(v)) : defValue;
    }

    @Override
    public long getLong(String key, long defValue) {
        final String v = delegate.getString(encrypt(key), null);
        return v != null ? Long.parseLong(decrypt(v)) : defValue;
    }

    @Override
    public float getFloat(String key, float defValue) {
        final String v = delegate.getString(encrypt(key), null);
        return v != null ? Float.parseFloat(decrypt(v)) : defValue;
    }

    @Override
    public boolean getBoolean(String key, boolean defValue) {
        final String v = delegate.getString(encrypt(key), null);
        return v != null ? Boolean.parseBoolean(decrypt(v)) : defValue;
    }

    @Override
    public boolean contains(String key) {
        key = encryptKey(key);
        return delegate.contains(key);
    }

    @Override
    public Editor edit() {
        return new Editor();
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        delegate.registerOnSharedPreferenceChangeListener(listener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        delegate.unregisterOnSharedPreferenceChangeListener(listener);
    }

    public class Editor implements SharedPreferences.Editor {

        protected SharedPreferences.Editor delegate;

        public Editor() {
            this.delegate = ObscuredSharedPreferences.this.delegate.edit();
        }

        @Override
        public void apply() {
            delegate.apply();
        }

        @Override
        public SharedPreferences.Editor putString(String key, String value) {
            delegate.putString(encryptKey(key), encrypt(value));
            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String key, Set<String> values) {
            delegate.putStringSet(encryptKey(key), encryptSet(values));
            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            delegate.putString(encryptKey(key), encrypt(Integer.toString(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            delegate.putString(encryptKey(key), encrypt(Long.toString(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            delegate.putString(encryptKey(key), encrypt(Float.toString(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            delegate.putString(encryptKey(key), encrypt(Boolean.toString(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            delegate.remove(encryptKey(key));
            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            delegate.clear();
            return this;
        }

        @Override
        public boolean commit() {
            return delegate.commit();
        }
    }
}
