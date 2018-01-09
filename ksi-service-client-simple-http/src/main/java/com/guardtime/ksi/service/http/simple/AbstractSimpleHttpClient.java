/*
 * Copyright 2013-2017 Guardtime, Inc.
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
import com.guardtime.ksi.service.client.http.HTTPConnectionParameters;
import com.guardtime.ksi.service.client.http.HttpSettings;
import com.guardtime.ksi.util.Base64;
import com.guardtime.ksi.util.Util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.URLConnection;

import static com.guardtime.ksi.service.client.http.AbstractHttpClient.HEADER_APPLICATION_KSI_REQUEST;
import static com.guardtime.ksi.service.client.http.AbstractHttpClient.HEADER_NAME_CONTENT_TYPE;

/**
 * Abstract simple HTTP client.
 */
abstract class AbstractSimpleHttpClient{

    static final String REQUEST_METHOD_GET = "GET";
    private static final String REQUEST_METHOD_POST = "POST";

    private final HttpSettings settings;

    AbstractSimpleHttpClient(HttpSettings settings) {
        Util.notNull(settings, "HTTP client settings");
        this.settings = settings;
    }

    SimpleHttpPostRequestFuture post(InputStream request) throws KSIClientException {
        OutputStream outputStream = null;
        try {
            HttpURLConnection connection = getConnection();
            connection.setRequestProperty(HEADER_NAME_CONTENT_TYPE, HEADER_APPLICATION_KSI_REQUEST);
            connection.setRequestMethod(REQUEST_METHOD_POST);
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

    HttpURLConnection getConnection() throws IOException {
        URLConnection connection;
        HTTPConnectionParameters params = settings.getParameters();
        if (params.getProxyUrl() != null) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP,
                    new InetSocketAddress(params.getProxyUrl().getHost(), params.getProxyUrl().getPort()));
            connection = settings.getUrl().openConnection(proxy);
        } else {
            connection = settings.getUrl().openConnection();
        }

        if (!(connection instanceof HttpURLConnection)) {
            throw new ProtocolException("Not an HTTP URL: " + settings.getUrl());
        }

        if (params.getConnectionTimeout() != -1) {
            connection.setConnectTimeout(params.getConnectionTimeout());
        }

        if (params.getReadTimeout() != -1) {
            connection.setReadTimeout(params.getReadTimeout());
        }

        if (params.getProxyUser() != null && !"".equals(params.getProxyUser())) {
            String auth = "Basic " + Base64.encode(Util.toByteArray(params.getProxyUser() + ":" + params.getProxyPassword()));
            connection.setRequestProperty("Proxy-Authorization", auth);
        }

        return ((HttpURLConnection) connection);
    }

    String getUrl(){
        return settings.getUrl().toString();
    }

}
