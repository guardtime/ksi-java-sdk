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
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.tasks.AggregatorConfigurationTask;
import com.guardtime.ksi.service.ha.tasks.ServiceCallingTask;
import com.guardtime.ksi.service.ha.tasks.SigningTask;
import com.guardtime.ksi.util.Util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * KSI Signing Client which combines other clients to achieve redundancy.
 *
 * NB! It is highly recommended that all the aggregator configurations would be in sync with each other (except credentials).
 * If that is not the case then SigningHAClient will log a warning but it will still work. If user asks for configuration from the
 * SigningHAClient it will use the most conservative configuration of sub clients to compose aggregated configuration.
 */
public class SigningHAClient extends AbstractHAClient<KSISigningClient, AggregationResponse, AggregatorConfiguration>
        implements KSISigningClient {

    /**
     * Used to initialize SigningHAClient.
     *
     * @param signingClients
     *          List of subclients to send the signing requests.
     */
    public SigningHAClient(List<KSISigningClient> signingClients) {
        super(signingClients);
    }

    /**
     * Does a non-blocking signing request. Sends the request to all the subclients in parallel. First successful response is
     * used, others are cancelled. Request fails only if all the subclients fail.
     *
     * @see KSISigningClient#sign(KSIRequestContext, DataHash, Long)
     */
    public Future<AggregationResponse> sign(KSIRequestContext requestContext, DataHash dataHash, Long level) throws KSIException {
        Util.notNull(requestContext, "requestContext");
        Util.notNull(dataHash, "dataHash");
        Util.notNull(level, "level");
        Collection<KSISigningClient> clients = getSubclients();
        final Collection<ServiceCallingTask<AggregationResponse>> tasks = new ArrayList<ServiceCallingTask<AggregationResponse>>(clients.size());
        for (KSISigningClient client : clients) {
            tasks.add(new SigningTask(client, requestContext, dataHash, level));
        }
        return callAnyService(tasks);
    }

    /**
     * Used to get an aggregated configuration composed of subclients configurations.
     * Configuration requests are sent to all the subclients.
     *
     * @see HAAggregatorConfiguration
     *
     * @param requestContext - instance of {@link KSIRequestContext}.
     * @return Aggregated aggregators configuration.
     * @throws KSIException if all the subclients fail
     */
    public AggregatorConfiguration getAggregatorConfiguration(KSIRequestContext requestContext) throws KSIException {
        Util.notNull(requestContext, "requestContext");
        Collection<Callable<AggregatorConfiguration>> tasks = new ArrayList<Callable<AggregatorConfiguration>>();
        for (KSISigningClient client : getSubclients()) {
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
                    "}", conf.getMaximumRequests(), conf.getParents(), conf.getMaximumLevel(), conf.getAggregationAlgorithm(),
                    conf.getAggregationPeriod()));
            if (i != configurations.size() - 1) {
                sb.append(",");
            }
        }
        return sb.toString();
    }

    protected AggregatorConfiguration aggregateConfigurations(List<AggregatorConfiguration> configurations) {
        return new HAAggregatorConfiguration(configurations);
    }
}
