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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.ExtensionResponseFuture;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.selectionmaker.RoundRobinSelectionMaker;
import com.guardtime.ksi.service.ha.selectionmaker.SelectionMaker;
import com.guardtime.ksi.service.ha.settings.HAClientSettings;
import com.guardtime.ksi.tlv.TLVElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * KSI Signing Client which combines other clients for high availability and load balancing purposes. TODO: NB!!! This is still
 * work in progress. Client picking strategy is working but sending request to multiple clients in parallel currently is not.
 */
public class HAClient implements KSISigningClient, KSIExtenderClient {

    private final static Logger LOGGER = LoggerFactory.getLogger(HAClient.class);
    private final SelectionMaker<KSISigningClient> ksiSigningClientsPicker;
    private final SelectionMaker<KSIExtenderClient> ksiExtenderClientsPicker;

    public HAClient(List<KSISigningClient> signingClients, List<KSIExtenderClient> extenderClients) throws KSIException {
        this(signingClients, extenderClients, createDefaultSettings(signingClients, extenderClients));
    }

    public HAClient(List<KSISigningClient> signingClients, List<KSIExtenderClient> extenderClients, HAClientSettings settings)
            throws KSIClientException {
        if (signingClients == null) {
            signingClients = Collections.emptyList();
        }
        if (extenderClients == null) {
            extenderClients = Collections.emptyList();
        }
        if (settings.getActiveSigningClientsPerRequest() > signingClients.size()) {
            throw new KSIClientException("Invalid input parameter. Property HAClientSettings.activeSigningClientsPerRequest must not " +
                    "be larger than the list of given KSI signing clients");
        }
        if (settings.getActiveExtenderClientsPerRequest() > extenderClients.size()) {
            throw new KSIClientException("Invalid input parameter. Property HAClientSettings.activeExtenderClientsPerRequest must not" +
                    " be larger than the list of given KSI extender clients");
        }
        this.ksiSigningClientsPicker = new RoundRobinSelectionMaker<KSISigningClient>(signingClients,
                settings.getActiveSigningClientsPerRequest());
        this.ksiExtenderClientsPicker = new RoundRobinSelectionMaker<KSIExtenderClient>(extenderClients,
                settings.getActiveExtenderClientsPerRequest());
        LOGGER.debug("High availability signing client initialized with settings %s and %d signing clients", settings,
                signingClients.size());
    }

    public Future<AggregationResponse> sign(KSIRequestContext requestContext, DataHash dataHash, Long level) throws KSIException {
        Collection<KSISigningClient> clients = ksiSigningClientsPicker.makeSelection();
        if (clients.isEmpty()) {
            throw new KSIClientException("It is impossible to perform a signing request using this HAClient because there are no " +
                    "signing clients in selection");
        }
        return clients.iterator().next().sign(requestContext, dataHash, level);
    }

    public ExtensionResponseFuture extend(KSIRequestContext requestContext, Date aggregationTime, Date publicationTime)
            throws KSIException {
        Collection<KSIExtenderClient> clients = ksiExtenderClientsPicker.makeSelection();
        if (clients.isEmpty()) {
            throw new KSIClientException("It is impossible to perform a signing request using this HAClient because there are no " +
                    "extending clients in selection");
        }
        return clients.iterator().next().extend(requestContext, aggregationTime, publicationTime);
    }

    public void close() throws IOException {
        for (KSISigningClient client : ksiSigningClientsPicker.getAll()) {
            try {
                client.close();
            } catch (IOException e) {
                LOGGER.error("Failed to close one of the HAClient KSISigningClients.", e);
            }
        }
        for (KSIExtenderClient client : ksiExtenderClientsPicker.getAll()) {
            try {
                client.close();
            } catch (IOException e) {
                LOGGER.error("Failed to close one of the HAClient KSISigningClients.", e);
            }
        }
    }

    private static HAClientSettings createDefaultSettings(List<KSISigningClient> signingClients, List<KSIExtenderClient>
            extenderClients) throws KSIException {
        return new HAClientSettings(signingClients == null ? 0 : signingClients.size(), extenderClients == null ? 0 :
                extenderClients.size());
    }

    @Override
    public String toString() {
        return "HAClient{LB Strategy=" + ksiSigningClientsPicker + "}";
    }

    public Future<TLVElement> sign(InputStream request) throws KSIClientException {
        throw new KSIClientException("HAClient.sign(inputStream) is not supported. Use " +
                "HAClient.sign(ksiRequestContext, dataHash, level) instead");
    }

    public Future<TLVElement> extend(InputStream request) throws KSIClientException {
        throw new KSIClientException("HAClient.extend(inputStream) is not supported. Use " +
                "HAClient.extend(ksiRequestContext, aggregationTime, publicationTime) instead");
    }
}
