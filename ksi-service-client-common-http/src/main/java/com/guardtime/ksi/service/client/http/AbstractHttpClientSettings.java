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

import java.net.URL;

/**
 * Abstract class for HTTP client configuration.
 */
public abstract class AbstractHttpClientSettings {

    private static final int UNDEFINED_TIMEOUT = -1;

    /**
     * Returns the signing service URL
     */
    public abstract URL getSigningUrl();

    /**
     * Returns the extender service URL
     */
    public abstract URL getExtendingUrl();

    /**
     * Returns the publications file URL
     */
    public abstract URL getPublicationsFileUrl();

    /**
     * Returns the service credentials.
     */
    public abstract ServiceCredentials getCredentials();

    /**
     * Returns the PDU version
     */
    public abstract PduVersion getPduVersion();

    /**
     * Returns the proxy URL. By default proxy isn't used and null is returned.
     */
    public URL getProxyUrl() {
        return null;
    }

    /**
     * Returns the proxy username. By default proxy isn't used and null is returned.
     */
    public String getProxyUser() {
        return null;
    }

    /**
     * Returns the proxy user password. By default proxy isn't used and null is returned.
     */
    public String getProxyPassword() {
        return null;
    }

    /**
     * Determines the timeout in milliseconds until a connection is established.
     * <p>
     * A timeout value of zero is interpreted as an infinite timeout. A negative value is interpreted as undefined
     * (system default).
     * <p>
     * Default value is -1.
     */
    public int getConnectionTimeout() {
        return UNDEFINED_TIMEOUT;
    }

    /**
     * Defines the socket read timeout in milliseconds, which is the timeout for waiting for data or a maximum period
     * inactivity between two consecutive data packets.
     * <p>
     * A timeout value of zero is interpreted as an infinite timeout. A negative value is interpreted as undefined
     * (system default).
     * <p>
     * Default value is -1.
     */
    public int getReadTimeout() {
        return UNDEFINED_TIMEOUT;
    }

}
