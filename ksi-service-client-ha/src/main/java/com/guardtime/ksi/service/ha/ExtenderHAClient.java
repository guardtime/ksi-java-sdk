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
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.ha.tasks.ExtenderConfigurationTask;
import com.guardtime.ksi.service.ha.tasks.ExtendingTask;
import com.guardtime.ksi.service.ha.tasks.ServiceCallingTask;
import com.guardtime.ksi.util.Util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * KSI Extender Client which combines other clients to achieve high availability and load balancing.
 *
 * NB! It is highly recommended that all the extender configurations would be in sync with each other (except credentials). If that is not the case then ExtenderHAClient will log a warning but it will still work.
 * If user asks for configuration from the ExtenderHAClient it will use the most conservative configuration of sub clients to compose aggregated configuration. Some parameters like maximum requests in a second take
 * account that there are multiple clients and if load balancing is enabled between those clients then those parameters are adjusted accordingly. This means that the user of the API can rely on this configuration
 * without worrying if load balancing is actually configured or not.
 */
public class ExtenderHAClient extends AbstractHAClient<KSIExtenderClient, ExtensionResponse, ExtenderConfiguration> implements KSIExtenderClient {

    /**
     * Used to initialize ExtenderHAClient in full high availability mode (load-balancing turned off).
     *
     * @param extenderClients
     *          List of subclients to send the extending requests.
     */
    public ExtenderHAClient(List<KSIExtenderClient> extenderClients) throws KSIException {
        this(extenderClients, null);
    }

    /**
     * Used to initialize ExtenderHAClient with load balancing enabled.
     *
     * @param extenderClients
     *          List of subclients to send the extending requests.
     * @param clientsForRequest
     *          Determines to how many clients any single request is sent in parallel. If that number is smaller than size of
     *          extenderClients, then Round-robin algorithm is used to load-balance between different requests. If it's set to
     *          null then ExtenderHAClient is initialized in full high availability mode (load-balancing turned off).
     *
     */
    public ExtenderHAClient(List<KSIExtenderClient> extenderClients, Integer clientsForRequest) {
        super(extenderClients, clientsForRequest);
    }

    /**
     * Does a non-blocking extending request. Picks clients to send the request, based on the configuration and sends the request
     * to all of them in parallel. First successful response is used, others are cancelled. Request fails only if all the
     * subclients fail.
     *
     * @see KSIExtenderClient#extend(KSIRequestContext, Date, Date)
     */
    public Future<ExtensionResponse> extend(KSIRequestContext requestContext, Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(requestContext, "requestContext");
        Util.notNull(aggregationTime, "aggregationTime");
        Collection<KSIExtenderClient> clients = prepareClients();
        Collection<ServiceCallingTask<ExtensionResponse>> tasks = new ArrayList<ServiceCallingTask<ExtensionResponse>>();
        for (KSIExtenderClient client : clients) {
            tasks.add(new ExtendingTask(client, requestContext, aggregationTime, publicationTime));
        }
        return callAnyService(tasks);
    }

    /**
     * Used to get an aggregated configuration composed of subclients configurations. Load-balancing does not apply here.
     * Configuration requests are sent to all the subclients.
     *
     * @see HAExtenderConfiguration
     *
     * @param requestContext
     *                       Instance of {@link KSIRequestContext}.
     * @return Aggregated extenders configuration.
     * @throws KSIException if all the subclients fail.
     */
    public ExtenderConfiguration getExtenderConfiguration(KSIRequestContext requestContext) throws KSIException {
        Util.notNull(requestContext, "requestContext");
        Collection<Callable<ExtenderConfiguration>> tasks = new ArrayList<Callable<ExtenderConfiguration>>();
        for (KSIExtenderClient client : getAllSubclients()) {
            tasks.add(new ExtenderConfigurationTask(requestContext, client));
        }
        return getConfiguration(tasks);
    }

    protected ExtenderConfiguration aggregateConfigurations(List<ExtenderConfiguration> configurations) {
        return new HAExtenderConfiguration(configurations, getAllSubclients().size(), getRequestClientselectionSize());
    }

    protected boolean configurationsEqual(ExtenderConfiguration c1, ExtenderConfiguration c2) {
        return Util.equals(c1.getMaximumRequests(), c2.getMaximumRequests()) &&
                Util.equals(c1.getCalendarFirstTime(), c2.getCalendarFirstTime()) &&
                Util.equals(c1.getCalendarLastTime(), c2.getCalendarLastTime()) &&
                Util.equalsIgnoreOrder(c1.getParents(), c2.getParents());
    }

    protected String configurationsToString(List<ExtenderConfiguration> configurations) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < configurations.size(); i++) {
            ExtenderConfiguration conf = configurations.get(i);
            sb.append(String.format("ExtenderConfiguration{" +
                    "maximumRequests='%s'," +
                    "parents='%s'," +
                    "calendarFirstTime='%s'," +
                    "calendarLastTime='%s'" +
                    "}", conf.getMaximumRequests(), conf.getParents(), conf.getCalendarFirstTime(), conf.getCalendarLastTime()));
            if (i != configurations.size() - 1) {
                sb.append(",");
            }
        }
        return sb.toString();
    }
}
