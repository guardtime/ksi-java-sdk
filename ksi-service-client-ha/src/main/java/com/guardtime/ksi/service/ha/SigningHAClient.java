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
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.settings.SingleFunctionHAClientSettings;
import com.guardtime.ksi.service.ha.tasks.AggregatorConfigurationTask;
import com.guardtime.ksi.service.ha.tasks.ServiceCallingTask;
import com.guardtime.ksi.service.ha.tasks.SigningTask;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * KSI Signing Client which combines other clients to achieve high availability and for load balancing.
 *
 * NB! It is highly recommended that all the aggregator configurations would be in sync with each other (except login accounts). If that is not the case then SigningHAClient will log a warning but it will still work.
 * If user asks for configuration from the SigningHAClient it will use the most conservative configuration of sub clients to compose aggregated configuration. Some parameters like maximum requests in a second take
 * account that there are multiple clients and if load balancing is enabled between those clients then those parameters are adjusted accordingly. This means that the user of the API can rely on this configuration
 * without worrying if load balancing is actually configured or not.
 */
public class SigningHAClient extends AbstractHAClient<KSISigningClient, AggregationResponse, AggregatorConfiguration> implements KSISigningClient {

    public SigningHAClient(List<KSISigningClient> subclients) throws KSIException {
        this(subclients, null);
    }

    public SigningHAClient(List<KSISigningClient> signingClients, SingleFunctionHAClientSettings settings) throws
            KSIException {
        super(signingClients, settings);
    }

    public AggregatorConfiguration getAggregatorsConfiguration(KSIRequestContext requestContext) throws KSIException {
        Collection<Callable<AggregatorConfiguration>> tasks = new ArrayList<Callable<AggregatorConfiguration>>();
        for (KSISigningClient client : getAllSubclients()) {
            tasks.add(new AggregatorConfigurationTask(requestContext, client));
        }
        return getConfiguration(tasks);
    }

    protected boolean configurationsEqual(AggregatorConfiguration c1, AggregatorConfiguration c2) {
        return Util.equals(c1.getMaximumLevel(), c2.getMaximumLevel()) &&
                Util.equals(c1.getAggregationAlgorithm(), c2.getAggregationAlgorithm()) &&
                Util.equals(c1.getAggregationPeriod(), c2.getAggregationPeriod()) &&
                Util.equals(c1.getMaximumRequests(), c2.getMaximumRequests()) &&
                Util.equalsIgnoreOrder(c1.getParents(), c2.getParents());
    }


    protected String configurationsToString(List<AggregatorConfiguration> configurations) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < configurations.size(); i++) {
            AggregatorConfiguration conf = configurations.get(i);
            sb.append(String.format("AggregatorConfiguration{" +
                    "maximumRequests='%s'," +
                    "parents='%s'," +
                    "maxLevel='%s'," +
                    "aggregationAlgorithm='%s'," +
                    "aggregationPeriod='%s'" +
                    "}", conf.getMaximumRequests(), conf.getParents(), conf.getMaximumLevel(), conf.getAggregationAlgorithm(), conf.getAggregationPeriod()));
            if (i != configurations.size() - 1) {
                sb.append(",");
            }
        }
        return sb.toString();
    }

    protected AggregatorConfiguration aggregateConfigurations(List<AggregatorConfiguration> configurations) {
        return new HAAggregatorConfiguration(configurations, getAllSubclients().size(), getRequestClientselectionSize());
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
        return callAnyService(tasks, requestId);
    }
}
