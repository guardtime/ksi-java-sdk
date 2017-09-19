/*
 * Copyright 2013-2016 Guardtime, Inc.
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
package com.guardtime.ksi.service.http.simple;

import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.http.AbstractHttpClient;
import com.guardtime.ksi.service.client.http.AbstractHttpClientSettings;
import com.guardtime.ksi.service.client.http.CredentialsAwareHttpSettings;
import com.guardtime.ksi.service.client.http.HTTPConnectionParameters;
import com.guardtime.ksi.service.client.http.HttpSettings;

import java.io.InputStream;

/**
 * Simple HTTP client
 */
public class SimpleHttpClient extends AbstractHttpClient {

    private SimpleHttpSigningClient signingClient;
    private SimpleHttpExtenderClient extenderClient;
    private SimpleHttpPublicationsFileClient publicationsFileClient;

    public SimpleHttpClient(AbstractHttpClientSettings settings) {
        super(settings);
        HTTPConnectionParameters params =
                new HTTPConnectionParameters(settings.getConnectionTimeout(), settings.getReadTimeout());
        params.setProxyUrl(settings.getProxyUrl());
        params.setProxyUser(settings.getProxyUser());
        params.setProxyPassword(settings.getProxyPassword());
        signingClient = new SimpleHttpSigningClient(
                new CredentialsAwareHttpSettings(settings.getSigningUrl().toString(), settings.getCredentials(), params));
        extenderClient = new SimpleHttpExtenderClient(
                new CredentialsAwareHttpSettings(settings.getExtendingUrl().toString(), settings.getCredentials(), params));
        publicationsFileClient =
                new SimpleHttpPublicationsFileClient(new HttpSettings(settings.getPublicationsFileUrl().toString()));
    }

    public SimpleHttpPostRequestFuture sign(InputStream request) throws KSIClientException {
        return signingClient.sign(request);
    }

    public SimpleHttpPostRequestFuture extend(InputStream request) throws KSIClientException {
        return extenderClient.extend(request);
    }

    public SimpleHttpGetRequestFuture getPublicationsFile() throws KSIClientException {
        return publicationsFileClient.getPublicationsFile();
    }

    public void close() {
        signingClient.close();
        extenderClient.close();
        publicationsFileClient.close();
    }

    @Override
    public String toString() {
        return "SimpleHttpClient{Gateway='" + signingClient.getUrl()
            + "', Extender='" + extenderClient.getUrl()
            + "', Publications='" + publicationsFileClient.getUrl()
            + "', Signer LoginID='" + signingClient.getServiceCredentials().getLoginId()
            + "', Extender LoginID='" + extenderClient.getServiceCredentials().getLoginId()
            + "', Signer PDUVersion='" + signingClient.getPduVersion()
            + "', Extender PDUVersion='" + signingClient.getPduVersion() +"'}";
    }

}
