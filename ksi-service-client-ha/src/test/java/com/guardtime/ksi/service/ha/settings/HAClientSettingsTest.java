package com.guardtime.ksi.service.ha.settings;

import com.guardtime.ksi.exceptions.KSIException;
import org.testng.annotations.Test;

public class HAClientSettingsTest {

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Property " +
            "activeSigningClientsPerRequest must not be smaller than 1")
    public void testActiveClientsPerRequestSmallerThanOne() throws Exception {
        new HAClientSettings(0, 1);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Property " +
            "threadPoolSize must not be smaller than 1")
    public void testThreadPoolSizeSetToSmallerThanOne() throws Exception {
        new HAClientSettings(1, 0);
    }

}
