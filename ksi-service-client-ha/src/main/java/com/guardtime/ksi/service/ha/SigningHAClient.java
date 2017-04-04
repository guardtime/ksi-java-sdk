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
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.settings.SingleFunctionHAClientSettings;
import com.guardtime.ksi.service.ha.tasks.ServiceCallingTask;
import com.guardtime.ksi.service.ha.tasks.SigningTask;
import com.guardtime.ksi.tlv.TLVElement;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * KSI Signing Client which combines other clients for high availability and load balancing purposes.
 */
public class SigningHAClient extends AbstractHAClient<KSISigningClient, AggregationResponse> implements KSISigningClient {

    public SigningHAClient(List<KSISigningClient> subclients) throws KSIException {
        this(subclients, null);
    }

    public SigningHAClient(List<KSISigningClient> signingClients, SingleFunctionHAClientSettings settings) throws
            KSIException {
        super(signingClients, settings);
    }

    public Future<TLVElement> sign(InputStream request) throws KSIClientException {
        throw new KSIClientException("SigningHAClient.sign(inputStream) is not supported. Use SignerHAClient.sign" +
                "(ksiRequestContext, dataHash, level) instead");
    }

    public Future<AggregationResponse> sign(KSIRequestContext requestContext, DataHash dataHash, Long level) throws KSIException {
        final Long requestId = requestContext.getRequestId();
        Collection<KSISigningClient> clients = preprareClients();
        final Collection<ServiceCallingTask<AggregationResponse>> tasks = new ArrayList<ServiceCallingTask<AggregationResponse>>();
        for (KSISigningClient client : clients) {
            tasks.add(new SigningTask(client, requestContext, dataHash, level));
        }
        return callServices(tasks, requestId);
    }
}
