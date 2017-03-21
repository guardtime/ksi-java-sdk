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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.ha.clientpicker.KSIClientsPicker;
import com.guardtime.ksi.service.ha.clientpicker.RoundRobinKSIClientsPicker;
import com.guardtime.ksi.service.ha.settings.HAClientSettings;
import com.guardtime.ksi.tlv.TLVElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * KSI Signing Client which combines other clients for high availability and load balancing purposes.
 */
public class HAClient implements KSISigningClient {

    private final static Logger LOGGER = LoggerFactory.getLogger(HAClient.class);

    private final ServiceCredentials serviceCredentials;
    private final PduVersion pduVersion;
    private final KSIClientsPicker ksiClientsPicker;
    private final ExecutorService executorService;


    public HAClient(List<KSISigningClient> signingClients) throws KSIException {
        this(signingClients, new HAClientSettings(1, 1000));
    }

    public HAClient(List<KSISigningClient> signingClients, HAClientSettings settings) throws KSIException {
        validateInitializationParameters(signingClients, settings);
        this.serviceCredentials = signingClients.get(0).getServiceCredentials();
        this.pduVersion = signingClients.get(0).getPduVersion();
        this.ksiClientsPicker = new RoundRobinKSIClientsPicker(signingClients, settings.getActiveSigningClientsPerRequest());
        this.executorService = Executors.newFixedThreadPool(settings.getThreadPoolSize());
        LOGGER.debug("High availability signing client initialized with settings %s and %d signing clients", settings,
                signingClients.size());
    }

    public ServiceCredentials getServiceCredentials() {
        return serviceCredentials;
    }

    public PduVersion getPduVersion() {
        return pduVersion;
    }


    public Future<TLVElement> sign(final InputStream request) throws KSIClientException {
        Collection<KSISigningClient> clients = ksiClientsPicker.pick();
        return clients.iterator().next().sign(request);
    }

    public void close() throws IOException {
        ksiClientsPicker.close();
    }

    private void validateInitializationParameters(List<KSISigningClient> signingClients, HAClientSettings settings) throws KSIException {
        if (signingClients == null) {
            throw new KSIException("Invalid input parameter. KSI signing clients list must be present");
        }
        if (signingClients.isEmpty()) {
            throw new KSIException("Invalid input parameter. KSI signing clients list must contain at least one element");
        }
        if (signingClients.size() > 1) {
            for (int i = 1; i < signingClients.size(); i++) {
                KSISigningClient client1 = signingClients.get(i - 1);
                KSISigningClient client2 = signingClients.get(i);
                if (!client1.getServiceCredentials().equals(client2.getServiceCredentials())) {
                    throw new KSIException(
                            "Invalid input parameter. All the KSI signing clients must have the same service credentials");
                }
                if (client1.getPduVersion() != client2.getPduVersion()) {
                    throw new KSIException(
                            "Invalid input parameter. All the KSI signing clients must have the same PDU version");
                }
            }
        }
        if (settings.getActiveSigningClientsPerRequest() > signingClients.size()) {
            throw new KSIException("Invalid input parameter. Property HAClientSettings.aggregatorsPerRequest must not be larger" +
                    " than the list of given KSI signing clients");
        }
    }
}
