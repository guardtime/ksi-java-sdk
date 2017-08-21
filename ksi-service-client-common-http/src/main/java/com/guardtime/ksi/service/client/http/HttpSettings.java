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

import java.net.URL;

import static com.guardtime.ksi.util.Util.notNull;
import static com.guardtime.ksi.util.Util.toUrl;

/**
 * <p>HTTP settings</p>
 * HTTP Service settings consist of URL of KSI service and connections parameters.
 * Connection parameters hold HTTP connection settings like timeouts and proxy configuration.
 */
public class HttpSettings {

    private URL url;
    private HTTPConnectionParameters parameters = new HTTPConnectionParameters();

    /**
     * Create HTTP Service settings with provided parameters.
     *
     * @param signingUrl
     *         URL of KSI service
     */
    public HttpSettings(String url) {
        this(url,  null);
    }

    /**
     * Create HTTP Service settings with provided parameters.
     *
     * @param url
     *         URL of KSI service
     * @param parameters
     *         Connection parameters.
     */
    public HttpSettings(String url, HTTPConnectionParameters parameters) {
        notNull(url, "KSI service URL");
        this.url = toUrl(url);
        if (parameters != null) {
            this.parameters = parameters;
        }
    }

    /**
     * Returns the URL of the service.
     */
    public URL getUrl() {
        return url;
    }

    /**
     * @return Proxy URL.
     */
    public URL getProxyUrl() {
        return parameters.getProxyUrl();
    }

    /**
     * @return Proxy user.
     */
    public String getProxyUser() {
        return parameters.getProxyUser();
    }

    /**
     * @return Proxy password.
     */
    public String getProxyPassword() {
        return parameters.getProxyPassword();
    }

    /**
     * @return Connection timeout.
     */
    public int getConnectionTimeout() {
        return parameters.getConnectionTimeout();
    }

    /**
     * @return Read timeout.
     */
    public int getReadTimeout() {
        return parameters.getReadTimeout();
    }

    /**
     * @return Connection parameters.
     */
    public HTTPConnectionParameters getParameters() {
        return parameters;
    }

}
