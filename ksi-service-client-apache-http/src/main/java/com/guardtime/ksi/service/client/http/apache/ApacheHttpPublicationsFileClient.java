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
package com.guardtime.ksi.service.client.http.apache;

import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.http.HttpSettings;

/**
 * KSI HTTP client that uses Apache HTTP client library.
 */
public class ApacheHttpPublicationsFileClient extends AbstractApacheHttpClient implements KSIPublicationsFileClient {

    /**
     * Constructs ApacheHttpSigningClient with configuration values passed in.
     *
     * @param settings settings defined by {@link com.guardtime.ksi.service.client.http.HttpSettings}.
     */
    public ApacheHttpPublicationsFileClient(HttpSettings settings) {
        super(settings);
    }

    /**
     * Constructs ApacheHttpSigningClient with configuration values passed in.
     *
     * @param settings settings defined by {@link com.guardtime.ksi.service.client.http.HttpSettings}.
     * @param asyncConfiguration configuration defined by an instance of {@link ApacheHttpClientConfiguration}.
     */
    public ApacheHttpPublicationsFileClient(HttpSettings settings, ApacheHttpClientConfiguration asyncConfiguration) {
        super(settings, asyncConfiguration);
    }

    /**
     * @see com.guardtime.ksi.service.client.KSIPublicationsFileClient
     */
    public ApacheHttpGetRequestFuture getPublicationsFile() throws KSIClientException {
        return get();
    }

}
