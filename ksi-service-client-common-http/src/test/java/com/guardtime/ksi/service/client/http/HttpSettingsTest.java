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

import org.testng.annotations.Test;

import java.net.MalformedURLException;
import java.net.URL;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class HttpSettingsTest {

    @Test
    public void createServiceSettings() throws MalformedURLException {
        String url = "http://foo.bar:1234";
        HttpSettings settings = new HttpSettings(url);

        assertEquals(settings.getUrl().toString(), url);
        assertNull(settings.getProxyUrl());
        assertNull(settings.getProxyUser());
        assertNull(settings.getProxyPassword());
        assertEquals(settings.getConnectionTimeout(), -1);
        assertEquals(settings.getReadTimeout(), -1);
    }

    @Test
    public void createServiceSettingsWithConnectionParams() throws MalformedURLException {
        String url = "http://foo.bar:1234";
        URL proxyUrl = new URL("http://foo.bar:1234/proxyUrl");
        String proxyUser = "Username";
        String proxyPassword = "Password";
        int connectionTimeout = 100;
        int readTimeout = 200;

        HTTPConnectionParameters parameters = new HTTPConnectionParameters(connectionTimeout, readTimeout);
        parameters.setProxyUrl(proxyUrl);
        parameters.setProxyUser(proxyUser);
        parameters.setProxyPassword(proxyPassword);

        HttpSettings settings = new HttpSettings(url, parameters);

        assertEquals(settings.getUrl().toString(), url);
        assertEquals(settings.getProxyUrl(), proxyUrl);
        assertEquals(settings.getProxyUser(), proxyUser);
        assertEquals(settings.getProxyPassword(), proxyPassword);
        assertEquals(settings.getConnectionTimeout(), connectionTimeout);
        assertEquals(settings.getReadTimeout(), readTimeout);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void createServiceSettingsFromMalformedUrl() {
        new HttpSettings("hatetepe://foo.bar:1234");
    }


}
