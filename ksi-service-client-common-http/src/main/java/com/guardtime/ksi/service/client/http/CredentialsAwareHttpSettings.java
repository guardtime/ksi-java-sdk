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
import com.guardtime.ksi.service.client.ServiceCredentials;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * <p>Credentials aware HTTP client settings</p>
 * HTTP Service settings consist of service credentials, URL of KSI service and connections parameters.
 * Connection parameters hold HTTP connection settings like timeouts and proxy configuration.
 */
public class CredentialsAwareHttpSettings extends HttpSettings {

    private final ServiceCredentials credentials;
    private PduVersion pduVersion = PduVersion.V1;

    public CredentialsAwareHttpSettings(String url, ServiceCredentials credentials) {
        this(url, credentials, null);
    }

    public CredentialsAwareHttpSettings(String url, ServiceCredentials credentials, HTTPConnectionParameters parameters) {
        super(url, parameters);
        notNull(credentials, "Service credentials");
        this.credentials = credentials;
    }

    public ServiceCredentials getCredentials() {
        return credentials;
    }

    /**
     * Returns the PDU version
     */
    public PduVersion getPduVersion() {
        return pduVersion;
    }

    /**
     * Sets the PDU version
     */
    public void setPduVersion(PduVersion pduVersion) {
        this.pduVersion = pduVersion;
    }
}
