/*
 * Copyright 2013-2018 Guardtime, Inc.
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

package com.guardtime.ksi.service;

import com.guardtime.ksi.concurrency.DefaultExecutorServiceProvider;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.ExtensionResponseFuture;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduFactoryProvider;
import com.guardtime.ksi.pdu.RequestContextFactory;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * Adapter which wraps {@link KSIExtenderClient} so it can be used as {@link KSIExtendingService}.
 */
public final class KSIExtendingClientServiceAdapter implements KSIExtendingService {

    private final KSIExtenderClient client;
    private final RequestContextFactory requestContextFactory = RequestContextFactory.DEFAULT_FACTORY;
    private final ConfigurationHandler<ExtenderConfiguration> extenderConfHandler;
    private final PduFactory pduFactory;

    public KSIExtendingClientServiceAdapter(KSIExtenderClient client) {
        this(client, DefaultExecutorServiceProvider.getExecutorService());
    }

    public KSIExtendingClientServiceAdapter(KSIExtenderClient client, ExecutorService executorService) {
        Util.notNull(client, "KSIExtendingClientServiceAdapter.client");
        Util.notNull(executorService, "KSIExtendingClientServiceAdapter.executorService");
        this.client = client;
        this.pduFactory = PduFactoryProvider.get(client.getPduVersion());
        this.extenderConfHandler = new ConfigurationHandler<>(executorService);
    }

    public Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(aggregationTime, "aggregationTime");
        KSIRequestContext requestContext = requestContextFactory.createContext();
        ServiceCredentials credentials = client.getServiceCredentials();
        ExtensionRequest requestMessage = pduFactory.createExtensionRequest(requestContext, credentials, aggregationTime, publicationTime);
        ByteArrayInputStream requestStream = new ByteArrayInputStream(requestMessage.toByteArray());
        Future<TLVElement> extensionResponse = client.extend(requestStream);
        return new ExtensionResponseFuture(extensionResponse, requestContext, credentials, pduFactory);
    }

    public List<KSIExtendingService> getSubExtendingServices() {
        return Collections.emptyList();
    }

    public void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener) {
        extenderConfHandler.registerListener(listener);
    }

    public Future<ExtenderConfiguration> getExtendingConfiguration() {
        return new ConfigurationFuture<>(extenderConfHandler.doConfigurationUpdate(
                new ConfigurationRequest<ExtenderConfiguration>() {
                    public ExtenderConfiguration invoke() throws KSIException {
                        KSIRequestContext requestContext = requestContextFactory.createContext();
                        ServiceCredentials credentials = client.getServiceCredentials();
                        ExtensionRequest request = pduFactory.createExtensionConfigurationRequest(requestContext, credentials);
                        Future<TLVElement> future = client.extend(new ByteArrayInputStream(request.toByteArray()));
                        return pduFactory.readExtenderConfigurationResponse(credentials, future.getResult());
                    }
                }));
    }

    public void close() throws IOException {
        client.close();
    }

    @Override
    public String toString() {
        return "KSIExtendingClientServiceAdapter{" +
                "client=" + client +
                '}';
    }
}
