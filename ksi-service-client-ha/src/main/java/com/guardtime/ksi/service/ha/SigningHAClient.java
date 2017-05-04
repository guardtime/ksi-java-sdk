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
import com.guardtime.ksi.pdu.SubclientConfiguration;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.tasks.AggregatorConfigurationTask;
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
     * @see KSISigningClient#sign(DataHash, Long)
     */
    public Future<AggregationResponse> sign(DataHash dataHash, Long level) throws KSIException {
        Util.notNull(dataHash, "dataHash");
        Util.notNull(level, "level");
        Collection<KSISigningClient> clients = getSubclients();
        final Collection<Callable<AggregationResponse>> tasks = new ArrayList<Callable<AggregationResponse>>(clients.size());
        for (KSISigningClient client : clients) {
            tasks.add(new SigningTask(client, dataHash, level));
        }
        return callAnyService(tasks);
    }

    /**
     * Used to get an aggregated configuration composed of subclients configurations.
     * Configuration requests are sent to all the subclients.
     *
     * @see HAAggregatorConfiguration
     *
     * @return Aggregated aggregators configuration.
     * @throws KSIException if all the subclients fail
     */
    public AggregatorConfiguration getAggregatorConfiguration() throws KSIException {
        Collection<Callable<SubclientConfiguration<AggregatorConfiguration>>> tasks = new ArrayList<Callable<SubclientConfiguration<AggregatorConfiguration>>>();
        for (KSISigningClient client : getSubclients()) {
            tasks.add(new AggregatorConfigurationTask(client));
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

    protected String configurationsToString(List<SubclientConfiguration<AggregatorConfiguration>> configurations) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < configurations.size(); i++) {
            SubclientConfiguration<AggregatorConfiguration> response = configurations.get(i);
            String subclientKey = response.getSubclientKey();
            if (response.isSucceeded()) {
                sb.append(successResponseToString(subclientKey, response.getConfiguration()));
            } else {
                sb.append(failedResponseToString(subclientKey, response.getRequestFailureCause()));
            }
            if (i != configurations.size() - 1) {
                sb.append(",");
            }
        }
        return sb.toString();
    }

    private String successResponseToString(String clientId, AggregatorConfiguration conf) {
        return String.format("AggregatorConfiguration{" +
                "aggregatorId='%s'," +
                "maximumRequests='%s'," +
                "parents='%s'," +
                "maxLevel='%s'," +
                "aggregationAlgorithm='%s'," +
                "aggregationPeriod='%s'" +
                "}",
                clientId,
                conf.getMaximumRequests(),
                conf.getParents(),
                conf.getMaximumLevel(),
                conf.getAggregationAlgorithm(),
                conf.getAggregationPeriod());
    }

    private String failedResponseToString(String clientId, Throwable t) {
        return String.format("AggregatorConfiguration{" +
                        "aggregatorId='%s'," +
                        "failureCause='%s'" +
                        "}", clientId, Util.getStacktrace(t));
    }

    protected AggregatorConfiguration aggregateConfigurations(List<SubclientConfiguration<AggregatorConfiguration>> configurations) {
        return new HAAggregatorConfiguration(configurations);
    }
}
