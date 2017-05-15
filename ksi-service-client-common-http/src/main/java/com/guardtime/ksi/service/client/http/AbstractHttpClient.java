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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponseFuture;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.ExtensionResponseFuture;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduFactoryProvider;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.pdu.RequestContextFactory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.ConfigurationHandler;
import com.guardtime.ksi.service.client.ConfigurationRequest;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * Common class for all KSI HTTP clients
 */
public abstract class AbstractHttpClient implements KSISigningClient, KSIExtenderClient, KSIPublicationsFileClient {

    public static final String HEADER_APPLICATION_KSI_REQUEST = "application/ksi-request";
    public static final String HEADER_NAME_CONTENT_TYPE = "Content-Type";

    protected final AbstractHttpClientSettings settings;
    private final PduFactory pduFactory;
    private final RequestContextFactory requestContextFactory = RequestContextFactory.DEFAULT_FACTORY;
    private final ConfigurationHandler<AggregatorConfiguration> aggregatorConfHandler;
    private final ConfigurationHandler<ExtenderConfiguration> extenderConfHandler;

    public AbstractHttpClient(AbstractHttpClientSettings settings, ExecutorService executorService) {
        Util.notNull(executorService, "HttpClient.executorService");
        Util.notNull(settings, "HttpClient.settings");
        this.aggregatorConfHandler = new ConfigurationHandler<AggregatorConfiguration>(executorService);
        this.extenderConfHandler = new ConfigurationHandler<ExtenderConfiguration>(executorService);
        this.pduFactory = PduFactoryProvider.get(settings.getPduVersion());
        this.settings = settings;
    }

    /**
     * Creates the PDU for signing request with correct aggregator login information and PDU version and sends it to gateway.
     * Parses the response PDU.
     *
     * @param dataHash - instance of {@link DataHash} to be signed. May not be null.
     * @param level - level of the dataHash to be signed in the overall tree. May not be null.
     *
     * @return {@link AggregationResponseFuture}
     * @throws KSIException
     */
    public AggregationResponseFuture sign(DataHash dataHash, Long level) throws KSIException {
        Util.notNull(dataHash, "dataHash");
        Util.notNull(level, "level");
        KSIRequestContext requestContext = requestContextFactory.createContext();
        ServiceCredentials credentials = getServiceCredentials();
        Future<TLVElement> requestFuture = sign(new ByteArrayInputStream(pduFactory.createAggregationRequest(requestContext, credentials, dataHash, level).toByteArray()));
        return new AggregationResponseFuture(requestFuture, requestContext, credentials, pduFactory);
    }

    private AggregatorConfiguration getAggregatorConfiguration() throws KSIException {
        KSIRequestContext requestContext = requestContextFactory.createContext();
        ServiceCredentials credentials = getServiceCredentials();
        AggregationRequest requestMessage = pduFactory.createAggregatorConfigurationRequest(requestContext, credentials);
        Future<TLVElement> future = sign(new ByteArrayInputStream(requestMessage.toByteArray()));
        return pduFactory.readAggregatorConfigurationResponse(requestContext, credentials, future.getResult());
    }

    public ExtensionResponseFuture extend(Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(aggregationTime, "aggregationTime");
        KSIRequestContext requestContext = requestContextFactory.createContext();
        ServiceCredentials credentials = getServiceCredentials();
        ExtensionRequest requestMessage = pduFactory.createExtensionRequest(requestContext, credentials, aggregationTime, publicationTime);
        ByteArrayInputStream requestStream = new ByteArrayInputStream(requestMessage.toByteArray());
        HttpPostRequestFuture postRequestFuture = post(requestStream, settings.getExtendingUrl());
        return new ExtensionResponseFuture(postRequestFuture, requestContext, credentials, pduFactory);
    }

    private ExtenderConfiguration getExtenderConfiguration() throws KSIException {
        KSIRequestContext requestContext = requestContextFactory.createContext();
        ServiceCredentials credentials = getServiceCredentials();
        ExtensionRequest request = pduFactory.createExtensionConfigurationRequest(requestContext, credentials);
        Future<TLVElement> future = extend(new ByteArrayInputStream(request.toByteArray()));
        return pduFactory.readExtenderConfigurationResponse(credentials, future.getResult());
    }

    protected abstract Future<TLVElement> extend(InputStream request) throws KSIClientException;

    protected Future<TLVElement> sign(InputStream inputStream) throws KSIClientException {
        return post(inputStream, settings.getSigningUrl());
    }

    protected abstract HttpPostRequestFuture post(InputStream inputStream, URL url) throws KSIClientException;

    public ServiceCredentials getServiceCredentials() {
        return settings.getCredentials();
    }

    public PduVersion getPduVersion() {
        return settings.getPduVersion();
    }

    /**
     * Since this client does not have any subclients, it will always return an empty list.
     */
    public List<KSISigningClient> getSubSigningClients() {
        return Collections.emptyList();
    }

    /**
     * Since this client does not have any subclients, it will always return an empty list.
     */
    public List<KSIExtenderClient> getSubExtenderClients() {
        return Collections.emptyList();
    }

    public void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener) {
        aggregatorConfHandler.registerListener(listener);
    }

    public void updateAggregationConfiguration() throws KSIException {
        aggregatorConfHandler.doConfigurationUpdate(new ConfigurationRequest<AggregatorConfiguration>() {
            public AggregatorConfiguration invoke() throws KSIException {
                return getAggregatorConfiguration();
            }
        });
    }

    public void updateExtenderConfiguration() throws KSIException {
        extenderConfHandler.doConfigurationUpdate(new ConfigurationRequest<ExtenderConfiguration>() {
            public ExtenderConfiguration invoke() throws KSIException {
                return getExtenderConfiguration();
            }
        });
    }

    public void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener) {
        extenderConfHandler.registerListener(listener);
    }
}
