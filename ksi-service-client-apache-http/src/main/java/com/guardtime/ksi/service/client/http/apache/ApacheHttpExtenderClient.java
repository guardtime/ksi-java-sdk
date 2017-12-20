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
package com.guardtime.ksi.service.client.http.apache;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.client.http.CredentialsAwareHttpSettings;

import java.io.InputStream;

/**
 * KSI HTTP client that uses Apache HTTP client library.
 */
public class ApacheHttpExtenderClient extends AbstractApacheHttpClient implements KSIExtenderClient {

    private CredentialsAwareHttpSettings settings;
    /**
     * Constructs ApacheHttpExtenderClient with configuration values passed in.
     *
     * @param settings - Settings defined by {@link com.guardtime.ksi.service.client.http.CredentialsAwareHttpSettings}
     */
    public ApacheHttpExtenderClient(CredentialsAwareHttpSettings settings) {
        super(settings);
        this.settings = settings;
    }

    /**
     * Constructs ApacheHttpExtenderClient with configuration values passed in
     *
     * @param settings - Settings defined by {@link com.guardtime.ksi.service.client.http.HttpSettings}
     * @param asyncConfiguration - Configuration defined by an instance of {@link ApacheHttpClientConfiguration}
     */
    public ApacheHttpExtenderClient(CredentialsAwareHttpSettings settings, ApacheHttpClientConfiguration asyncConfiguration) {
        super(settings, asyncConfiguration);
        this.settings = settings;
    }

    /**
     * @see com.guardtime.ksi.service.client.KSIExtenderClient
     */
    public ApacheHttpPostRequestFuture extend(InputStream request) throws KSIClientException {
        return post(request);
    }

    public ServiceCredentials getServiceCredentials() {
        return settings.getCredentials();
    }

    public PduVersion getPduVersion() {
        return settings.getPduVersion();
    }

}
