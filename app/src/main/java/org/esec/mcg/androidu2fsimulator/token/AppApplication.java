package org.esec.mcg.androidu2fsimulator.token;

import android.app.Application;
import android.content.SharedPreferences;

import com.squareup.leakcanary.LeakCanary;
import com.squareup.leakcanary.RefWatcher;

import org.esec.mcg.androidu2fsimulator.token.secure.preference.core.KeyStoreKeyGenerator;
import org.esec.mcg.androidu2fsimulator.token.secure.preference.core.ObscuredPreferencesBuilder;
import org.esec.mcg.androidu2fsimulator.token.secure.preference.core.ObscuredSharedPreferences;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Created by yz on 2016/4/7.
 */
public class AppApplication extends Application {
    private static final int EIGEN_LENNGTH = 32;

    private RefWatcher mRefWatcher;

    private String eigenValue;

    @Override
    public void onCreate() {
        super.onCreate();
        mRefWatcher = LeakCanary.install(this);

        try {
            String key = KeyStoreKeyGenerator.get(this, getPackageName()).loadOrGenerateKeys();
            SharedPreferences sharedPreferences = new ObscuredPreferencesBuilder()
                    .setApplication(this)
                    .obfuscateKey(true)
                    .obfuscateValue(true)
                    .setSharePrefFileName("eigenvalue")
                    .setSecret(key)
                    .createSharedPrefs();
            if (sharedPreferences.contains("eigenvalue")) {
                eigenValue = sharedPreferences.getString("eigenvalue", null);
            } else {
                final byte[] raw = new byte[EIGEN_LENNGTH];
                new SecureRandom().nextBytes(raw);
                eigenValue = new String(raw);
                SharedPreferences.Editor editor = sharedPreferences.edit();
                editor.putString("eigenvalue", eigenValue);
                editor.commit();
            }
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public String getEigenValue() {
        return eigenValue;
    }

    public void setEigenValue(String eigenValue) {
        this.eigenValue = eigenValue;
    }
}
