/*
 * Copyright 2013-2017 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */
package com.guardtime.ksi.service.client.http;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.ServiceCredentials;
import org.testng.annotations.Test;

import java.net.MalformedURLException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class CredentialsAwareHttpSettingsTest {

    @Test
    public void createServiceSettings() throws MalformedURLException {
        String url = "http://foo.bar:1234";
        ServiceCredentials credentials = new KSIServiceCredentials("anon", "anon");
        CredentialsAwareHttpSettings settings = new CredentialsAwareHttpSettings(url, credentials);

        assertEquals(settings.getUrl().toString(), url);
        assertNull(settings.getProxyUrl());
        assertNull(settings.getProxyUser());
        assertNull(settings.getProxyPassword());
        assertEquals(settings.getConnectionTimeout(), -1);
        assertEquals(settings.getReadTimeout(), -1);
        assertEquals(settings.getPduVersion(), PduVersion.V2);
        assertEquals(settings.getCredentials().getLoginId(), credentials.getLoginId());
        assertEquals(settings.getCredentials().getLoginKey(), credentials.getLoginKey());
        assertEquals(settings.getCredentials().getHmacAlgorithm(), credentials.getHmacAlgorithm());
    }

    @Test(expectedExceptions = NullPointerException.class,
            expectedExceptionsMessageRegExp = "Service credentials can not be null")
    public void createServiceSettingsWithoutCredentials() throws MalformedURLException {
        String url = "http://foo.bar:1234";
        new CredentialsAwareHttpSettings(url, null);
    }

}
