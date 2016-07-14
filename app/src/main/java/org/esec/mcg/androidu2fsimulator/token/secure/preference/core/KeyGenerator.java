package org.esec.mcg.androidu2fsimulator.token.secure.preference.core;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Created by yz on 2016/7/13.
 */
public interface KeyGenerator {

    /**
     *
     * @return String key to be used in encryption algorithms
     * @throws GeneralSecurityException In case of Security Related exceptions
     * @throws IOException If could unable to read/write key
     */
    String loadOrGenerateKeys() throws GeneralSecurityException, IOException;

    /**
     *
     * @return boolean to know whether key is hardware a backed or not
     */
    boolean isHardwareBacked();
}
