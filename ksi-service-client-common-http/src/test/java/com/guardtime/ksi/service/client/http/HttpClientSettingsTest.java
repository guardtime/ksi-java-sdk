/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */
package com.guardtime.ksi.service.client.http;

import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.http.HttpClientSettings.HTTPConnectionParameters;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.net.MalformedURLException;
import java.net.URL;

public class HttpClientSettingsTest {

    private KSIServiceCredentials ANONYMOUS = new KSIServiceCredentials("anon", "anon");

    @Test
    public void createServiceSettings() throws MalformedURLException {

        String signingUrl = "http://foo.bar:1234/signingUrl";
        String extendingUrl = "http://foo.bar:1234/extendingUrl";
        String publicationsFileUrl = "http://foo.bar:1234/publicationsUrl";

        HttpClientSettings settings = new HttpClientSettings(signingUrl, extendingUrl, publicationsFileUrl, ANONYMOUS);

        URL proxyUrl = new URL("http://foo.bar:1234/proxyUrl");
        String proxyUser = "Username";
        String proxyPassword = "Password";
        int connectionTimeout = 123;
        int readTimeout = 123;

        HTTPConnectionParameters parameters = new HTTPConnectionParameters();
        parameters.setProxyUrl(proxyUrl);
        parameters.setProxyUser(proxyUser);
        parameters.setProxyPassword(proxyPassword);
        parameters.setConnectionTimeout(connectionTimeout);
        parameters.setReadTimeout(readTimeout);

        settings.setParameters(parameters);

        Assert.assertEquals(parameters.getProxyUrl(), proxyUrl);
        Assert.assertEquals(parameters.getProxyUser(), proxyUser);
        Assert.assertEquals(parameters.getProxyPassword(), proxyPassword);
        Assert.assertEquals(parameters.getConnectionTimeout(), connectionTimeout);
        Assert.assertEquals(parameters.getReadTimeout(), readTimeout);


        Assert.assertEquals(settings.getSigningUrl().toString(), signingUrl);
        Assert.assertEquals(settings.getExtendingUrl().toString(), extendingUrl);
        Assert.assertEquals(settings.getPublicationsFileUrl().toString(), publicationsFileUrl);
        Assert.assertEquals(settings.getParameters(), parameters);
    }


    @Test(expectedExceptions = IllegalArgumentException.class)
    public void createServiceSettingsFromMalformedExtendingUrl() {
        new HttpClientSettings("http://foo.bar:1234/signingUrl", "hatetepe://foo.bar:1234/extendingUrl", "http://foo.bar:1234/publicationsUrl", ANONYMOUS);
    }


    @Test(expectedExceptions = IllegalArgumentException.class)
    public void createServiceSettingsFromMalformedSigningUrl() {
        new HttpClientSettings("hatetepe://foo.bar:1234/signingUrl", "http://foo.bar:1234/extendingUrl", "http://foo.bar:1234/publicationsUrl", ANONYMOUS);
    }


    @Test(expectedExceptions = IllegalArgumentException.class)
    public void createServiceSettingsFromMalformedPublicationsUrl() {
        new HttpClientSettings("http://foo.bar:1234/signingUrl", "http://foo.bar:1234/extendingUrl", "hatetepe://foo.bar:1234/publicationsUrl", ANONYMOUS);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "credentials is null")
    public void createServiceSettingswithNullCredentials() {
        new HttpClientSettings("http://foo.bar:1234/signingUrl", "http://foo.bar:1234/extendingUrl", "http://foo.bar:1234/publicationsUrl", null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "loginKey is null")
    public void createServiceSettingswithNullLoginKey() {
        new KSIServiceCredentials("test", (String) null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "loginId is null")
    public void createServiceSettingswithNullLoginID() {
        new KSIServiceCredentials(null, "test");
    }

    @Test
    public void createServiceSettingswithTestCredentials() {
        HttpClientSettings settings = new HttpClientSettings("http://foo.bar:1234/signingUrl", "http://foo.bar:1234/extendingUrl", "http://foo.bar:1234/publicationsUrl", new KSIServiceCredentials("loginId", "loginKey"));
        Assert.assertEquals(settings.getCredentials().getLoginId(), "loginId");
        Assert.assertEquals(settings.getCredentials().getLoginKey(), "loginKey".getBytes());
    }

}
