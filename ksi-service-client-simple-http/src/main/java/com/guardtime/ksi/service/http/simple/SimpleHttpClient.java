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
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.http.AbstractHttpClient;
import com.guardtime.ksi.service.client.http.AbstractHttpClientSettings;
import com.guardtime.ksi.util.Base64;
import com.guardtime.ksi.util.Util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;

/**
 * Simple HTTP client
 */
public class SimpleHttpClient extends AbstractHttpClient implements KSISigningClient, KSIExtenderClient, KSIPublicationsFileClient {

    public SimpleHttpClient(AbstractHttpClientSettings settings) {
        super(settings);
    }

    public SimpleHttpPostRequestFuture sign(InputStream request) throws KSIClientException {
        return post(request, settings.getSigningUrl(), settings);
    }

    public SimpleHttpPostRequestFuture extend(InputStream request) throws KSIClientException {
        return post(request, settings.getExtendingUrl(), settings);
    }

    public SimpleHttpGetRequestFuture getPublicationsFile() throws KSIClientException {
        HttpURLConnection connection;
        try {
            connection = getConnection(settings.getPublicationsFileUrl(), settings);
            connection.setRequestMethod("GET");
            return new SimpleHttpGetRequestFuture(connection);
        } catch (IOException e) {
            throw new KSIClientException("HTTP request failed", e);
        }
    }

    private SimpleHttpPostRequestFuture post(InputStream request, URL url, AbstractHttpClientSettings settings) throws KSIClientException {
        OutputStream outputStream = null;
        try {
            HttpURLConnection connection = getConnection(url, settings);
            connection.setRequestProperty(HEADER_NAME_CONTENT_TYPE, HEADER_APPLICATION_KSI_REQUEST);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            outputStream = connection.getOutputStream();
            Util.copyData(request, outputStream);

            return new SimpleHttpPostRequestFuture(connection);
        } catch (IOException e) {
            throw new KSIClientException("HTTP request failed", e);
        } finally {
            Util.closeQuietly(outputStream);
        }
    }

    public HttpURLConnection getConnection(URL url, AbstractHttpClientSettings settings) throws IOException {
        URLConnection connection;
        if (settings.getProxyUrl() != null) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(settings.getProxyUrl().getHost(), settings.getProxyUrl().getPort()));
            connection = url.openConnection(proxy);
        } else {
            connection = url.openConnection();
        }

        if (!(connection instanceof HttpURLConnection)) {
            throw new ProtocolException("Not an HTTP URL: " + url);
        }

        if (settings.getConnectionTimeout() != -1) {
            connection.setConnectTimeout(settings.getConnectionTimeout());
        }

        if (settings.getReadTimeout() != -1) {
            connection.setReadTimeout(settings.getReadTimeout());
        }

        if (settings.getProxyUser() != null && !"".equals(settings.getProxyUser())) {
            String auth = "Basic " + Base64.encode(Util.toByteArray(settings.getProxyUser() + ":" + settings.getProxyPassword()));
            connection.setRequestProperty("Proxy-Authorization", auth);
        }

        return ((HttpURLConnection) connection);
    }

    public void close() {
    }

    @Override
    public String toString() {
        return "SimpleHttpClient{Gateway='" + settings.getSigningUrl() + "', Extender='" + settings.getExtendingUrl() + "', Publications='" + settings.getPublicationsFileUrl() + "', LoginID='" + getServiceCredentials().getLoginId() + "', PDUVersion='" + getPduVersion() + "'}";
    }

}
