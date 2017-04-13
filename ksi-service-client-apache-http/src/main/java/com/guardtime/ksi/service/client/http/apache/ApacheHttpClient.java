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

import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.http.AbstractHttpClient;
import com.guardtime.ksi.service.client.http.AbstractHttpClientSettings;
import com.guardtime.ksi.service.client.http.HttpClientSettings;
import com.guardtime.ksi.util.Util;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.impl.nio.reactor.IOReactorConfig;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.concurrent.Future;

/**
 * KSI HTTP client that uses Apache HTTP client library.
 */
public class ApacheHttpClient extends AbstractHttpClient implements KSISigningClient, KSIExtenderClient, KSIPublicationsFileClient {

    private CloseableHttpAsyncClient apacheClient;

    /**
     * Constructs ApacheHttpClient with configuration values defined by {@link ApacheHttpClientSimpleConfiguration}
     *
     * @param settings
     *         - Settings defined by {@link com.guardtime.ksi.service.client.http.HttpClientSettings}
     */
    public ApacheHttpClient(HttpClientSettings settings) {
        this(settings, new ApacheHttpClientSimpleConfiguration());
    }

    /**
     * Constructs ApacheHttpClient with configuration values passed in
     *
     * @param settings
     *         - Settings defined by {@link com.guardtime.ksi.service.client.http.HttpClientSettings}
     * @param asyncConfiguration
     *         - Configuration defined by an instance of {@link ApacheHttpClientConfiguration}
     */
    public ApacheHttpClient(AbstractHttpClientSettings settings, ApacheHttpClientConfiguration asyncConfiguration) {
        super(settings);
        this.apacheClient = createClient(settings, asyncConfiguration);
    }

    protected ApacheHttpPostRequestFuture sign(InputStream request) throws KSIClientException {
        return post(request, settings.getSigningUrl());
    }

    public ApacheHttpPostRequestFuture extend(InputStream request) throws KSIClientException {
        return post(request, settings.getExtendingUrl());
    }

    public ApacheHttpGetRequestFuture getPublicationsFile() throws KSIClientException {
        try {
            HttpGet httpRequest = new HttpGet(settings.getPublicationsFileUrl().toURI());
            return new ApacheHttpGetRequestFuture(apacheClient.execute(httpRequest, null));
        } catch (URISyntaxException e) {
            throw new KSIClientException("Invalid URI " + settings.getPublicationsFileUrl(), e);
        }
    }

    protected ApacheHttpPostRequestFuture post(InputStream request, URL url) throws KSIClientException {
        try {
            HttpPost httpRequest = new HttpPost(url.toURI());
            httpRequest.setHeader(AbstractHttpClient.HEADER_NAME_CONTENT_TYPE, AbstractHttpClient.HEADER_APPLICATION_KSI_REQUEST);
            ByteArrayEntity entity = new ByteArrayEntity(Util.toByteArray(request));
            entity.setChunked(false);
            httpRequest.setEntity(entity);
            Future<HttpResponse> future = this.apacheClient.execute(httpRequest, null);
            return new ApacheHttpPostRequestFuture(future);
        } catch (URISyntaxException e) {
            throw new KSIClientException("Invalid URI " + settings.getSigningUrl(), e);
        } catch (IOException e) {
            throw new KSIClientException("Reading data from stream failed", e);
        }
    }

    public void close() {
        try {
            apacheClient.close();
        } catch (IOException e) {
            // Ignore
        }
    }

    /**
     * Creates asynchronous Apache HTTP client.
     *
     * @param settings
     *         - settings to use to create client
     * @param conf
     *         - configuration related to async connection
     * @return instance of {@link CloseableHttpAsyncClient}
     */
    private CloseableHttpAsyncClient createClient(AbstractHttpClientSettings settings, ApacheHttpClientConfiguration conf) {
        IOReactorConfig ioReactor = IOReactorConfig.custom().setIoThreadCount(conf.getMaxThreadCount()).build();
        HttpAsyncClientBuilder httpClientBuilder = HttpAsyncClients.custom()
                .useSystemProperties()
                        // allow POST redirects
                .setRedirectStrategy(new LaxRedirectStrategy()).setMaxConnTotal(conf.getMaxTotalConnectionCount()).setMaxConnPerRoute(conf.getMaxRouteConnectionCount()).setDefaultIOReactorConfig(ioReactor)
                .setKeepAliveStrategy(new DefaultConnectionKeepAliveStrategy()).setDefaultRequestConfig(createDefaultRequestConfig(settings));
        if (settings.getProxyUrl() != null) {
            DefaultProxyRoutePlanner routePlanner = createProxyRoutePlanner(settings, httpClientBuilder);
            httpClientBuilder.setRoutePlanner(routePlanner);
        }
        CloseableHttpAsyncClient httpClient = httpClientBuilder.build();
        httpClient.start();
        return httpClient;
    }

    /**
     * Creates default proxy route planner
     *
     * @param settings
     *         - settings to use
     * @param httpClientBuilder
     *         - http client builder
     * @return instance of {@link DefaultProxyRoutePlanner}
     */
    private DefaultProxyRoutePlanner createProxyRoutePlanner(AbstractHttpClientSettings settings, HttpAsyncClientBuilder httpClientBuilder) {
        HttpHost proxy = new HttpHost(settings.getProxyUrl().getHost(), settings.getProxyUrl().getPort());
        if (settings.getProxyUser() != null) {
            CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            String proxyUser = settings.getProxyUser();
            String proxyPassword = settings.getProxyPassword();
            UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(proxyUser, proxyPassword);
            credentialsProvider.setCredentials(new AuthScope(proxy), credentials);
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
        }
        return new DefaultProxyRoutePlanner(proxy);
    }

    /**
     * Creates default request config
     *
     * @param settings
     *         settings to use
     * @return instance of {@link RequestConfig}
     */
    private RequestConfig createDefaultRequestConfig(AbstractHttpClientSettings settings) {
        int connectionTimeout = settings.getConnectionTimeout();
        int socketTimeout = settings.getReadTimeout();
        return RequestConfig.custom().setConnectionRequestTimeout(connectionTimeout).setSocketTimeout(socketTimeout).build();
    }

    @Override
    public String toString() {
        return "ApacheHttpClient{Gateway='" + settings.getSigningUrl() + "', Extender='" + settings.getExtendingUrl() + "', Publications='" + settings.getPublicationsFileUrl() + "', LoginID='" + getServiceCredentials().getLoginId() + "', PDUVersion='" + getPduVersion() + "'}";
    }
}
