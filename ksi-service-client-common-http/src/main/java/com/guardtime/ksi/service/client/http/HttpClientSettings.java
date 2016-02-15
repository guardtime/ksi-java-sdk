/*
 * Copyright 2013-2015 Guardtime, Inc.
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

import com.guardtime.ksi.service.client.ServiceCredentials;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * KSI client settings for HTTP endpoint. <p> HTTP Service settings consist of three URLs and connections parameters:
 * </p> <ul> <li>signingUrl - URL of KSI gateway for signing requests</li> <li>extendingUrl - URL of KSI extender for
 * extending requests</li> <li>publicationsFileUrl - URL of online publications file.</li> </ul>
 * <p/>
 * Connection parameters hold HTTP connection settings like timeouts and proxy configuration.
 */
public class HttpClientSettings extends AbstractHttpClientSettings {

    private URL extendingUrl;
    private URL signingUrl;
    private URL publicationsFileUrl;
    private HTTPConnectionParameters parameters = new HTTPConnectionParameters();
    private ServiceCredentials credentials;

    /**
     * Create HTTP Service settings with provided parameters.
     *
     * @param signingUrl
     *         URL of KSI gateway for signing requests
     * @param extendingUrl
     *         URL of KSI extender for extending requests
     * @param publicationsFileUrl
     *         URL of online publications file.
     * @param credentials
     *         service credentials
     */
    public HttpClientSettings(String signingUrl, String extendingUrl, String publicationsFileUrl, ServiceCredentials credentials) {
        if (extendingUrl == null) {
            throw new IllegalArgumentException("extending URL is null");
        }

        if (signingUrl == null) {
            throw new IllegalArgumentException("signing URL is null");
        }

        if (publicationsFileUrl == null) {
            throw new IllegalArgumentException("publications file URL is null");
        }

        if (credentials == null) {
            throw new IllegalArgumentException("credentials is null");
        }

        try {
            this.extendingUrl = new URL(extendingUrl);
            this.signingUrl = new URL(signingUrl);
            this.publicationsFileUrl = new URL(publicationsFileUrl);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("malformed Url", e);
        }

        this.credentials = credentials;
    }

    /**
     * @see AbstractHttpClientSettings#getSigningUrl()
     */
    @Override
    public URL getSigningUrl() {
        return signingUrl;
    }

    /**
     * @see AbstractHttpClientSettings#getExtendingUrl()
     */
    @Override
    public URL getExtendingUrl() {
        return extendingUrl;
    }

    /**
     * @see AbstractHttpClientSettings#getPublicationsFileUrl()
     */
    @Override
    public URL getPublicationsFileUrl() {
        return publicationsFileUrl;
    }

    /**
     * @see AbstractHttpClientSettings#getPublicationsFileUrl()
     */
    @Override
    public ServiceCredentials getCredentials() {
        return credentials;
    }

    /**
     * @see AbstractHttpClientSettings#getProxyUrl()
     */
    @Override
    public URL getProxyUrl() {
        return parameters.getProxyUrl();
    }

    /**
     * @see AbstractHttpClientSettings#getProxyUser()
     */
    @Override
    public String getProxyUser() {
        return parameters.getProxyUser();
    }

    /**
     * @see AbstractHttpClientSettings#getProxyPassword()
     */
    @Override
    public String getProxyPassword() {
        return parameters.getProxyPassword();
    }

    /**
     * @see AbstractHttpClientSettings#getConnectionTimeout()
     */
    @Override
    public int getConnectionTimeout() {
        return parameters.getConnectionTimeout();
    }

    /**
     * @see AbstractHttpClientSettings#getReadTimeout()
     */
    @Override
    public int getReadTimeout() {
        return parameters.getReadTimeout();
    }

    /**
     * @return connection parameters
     */
    public HTTPConnectionParameters getParameters() {
        return parameters;
    }

    /**
     * Set connection parameters.
     *
     * @param parameters
     *         http connection parameters
     */
    public void setParameters(HTTPConnectionParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * HTTP Connection parameters.
     * <p/>
     * Contains low level connection parameters for HTTP service.
     */
    public static class HTTPConnectionParameters {

        private URL proxyUrl;
        private String proxyUser;
        private String proxyPassword;

        private int connectionTimeout = -1;
        private int readTimeout = -1;

        /**
         * Create new HTTP Connection Parameters.
         */
        public HTTPConnectionParameters() {
        }

        /**
         * @return connection timeout
         */
        public int getConnectionTimeout() {
            return connectionTimeout;
        }

        /**
         * Set connection timeout.
         *
         * @param connectionTimeout
         *         connection timeout
         */
        public void setConnectionTimeout(int connectionTimeout) {
            this.connectionTimeout = connectionTimeout;
        }

        /**
         * @return proxy password
         */
        public String getProxyPassword() {
            return proxyPassword;
        }

        /**
         * Set proxy password.
         *
         * @param proxyPassword
         *         proxy password
         */
        public void setProxyPassword(String proxyPassword) {
            this.proxyPassword = proxyPassword;
        }

        /**
         * @return proxy URL.
         */
        public URL getProxyUrl() {
            return proxyUrl;
        }

        /**
         * Set proxy URL.
         *
         * @param proxyUrl
         *         proxy url
         */
        public void setProxyUrl(URL proxyUrl) {
            this.proxyUrl = proxyUrl;
        }

        /**
         * @return proxy username
         */
        public String getProxyUser() {
            return proxyUser;
        }

        /**
         * Set proxy username.
         *
         * @param proxyUser
         *         proxy user
         */
        public void setProxyUser(String proxyUser) {
            this.proxyUser = proxyUser;
        }

        /**
         * @return read timeout
         */
        public int getReadTimeout() {
            return readTimeout;
        }

        /**
         * Set read timeout.
         *
         * @param readTimeout
         *         read timeout
         */
        public void setReadTimeout(int readTimeout) {
            this.readTimeout = readTimeout;
        }
    }
}
