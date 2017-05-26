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
package com.guardtime.ksi.service.client.http;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.util.Util;

/**
 * Common class for all KSI HTTP clients
 */
public abstract class AbstractHttpClient implements KSISigningClient, KSIExtenderClient, KSIPublicationsFileClient {

    public static final String HEADER_APPLICATION_KSI_REQUEST = "application/ksi-request";
    public static final String HEADER_NAME_CONTENT_TYPE = "Content-Type";

    protected AbstractHttpClientSettings settings;

    public AbstractHttpClient(AbstractHttpClientSettings settings) {
        Util.notNull(settings, "HttpClient.settings");
        this.settings = settings;
    }

    public ServiceCredentials getServiceCredentials() {
        return settings.getCredentials();
    }

    public PduVersion getPduVersion() {
        return settings.getPduVersion();
    }

}
