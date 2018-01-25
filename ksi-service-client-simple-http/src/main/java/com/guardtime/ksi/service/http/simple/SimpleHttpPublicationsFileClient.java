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
package com.guardtime.ksi.service.http.simple;

import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.http.HttpSettings;

import java.io.IOException;
import java.net.HttpURLConnection;

/**
 * Simple HTTP client for retrieving publications file.
 */
public class SimpleHttpPublicationsFileClient extends AbstractSimpleHttpClient implements KSIPublicationsFileClient {

    public SimpleHttpPublicationsFileClient(HttpSettings settings) {
        super(settings);
    }

    /**
     * @see com.guardtime.ksi.service.client.KSIPublicationsFileClient
     */
    public SimpleHttpGetRequestFuture getPublicationsFile() throws KSIClientException {
        HttpURLConnection connection;
        try {
            connection = getConnection();
            connection.setRequestMethod(REQUEST_METHOD_GET);
            return new SimpleHttpGetRequestFuture(connection);
        } catch (IOException e) {
            throw new KSIClientException("HTTP request failed", e);
        }
    }

    public void close() {}

}
