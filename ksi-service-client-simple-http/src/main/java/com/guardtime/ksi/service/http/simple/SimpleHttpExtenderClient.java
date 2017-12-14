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

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.client.http.CredentialsAwareHttpSettings;

import java.io.InputStream;

/**
 * Simple HTTP client for extension operation.
 */
public class SimpleHttpExtenderClient extends AbstractSimpleHttpClient implements KSIExtenderClient {

    private CredentialsAwareHttpSettings settings;

    public SimpleHttpExtenderClient(CredentialsAwareHttpSettings settings) {
        super(settings);
        this.settings = settings;
    }

    /**
     * @see com.guardtime.ksi.service.client.KSIExtenderClient#extend(InputStream)
     */
    public SimpleHttpPostRequestFuture extend(InputStream request) throws KSIClientException {
        return post(request);
    }

    public void close() {}

    public ServiceCredentials getServiceCredentials() {
        return settings.getCredentials();
    }

    public PduVersion getPduVersion() {
        return settings.getPduVersion();
    }
}
