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
import com.guardtime.ksi.pdu.SubclientConfiguration;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.ha.tasks.ExtenderConfigurationTask;
import com.guardtime.ksi.service.ha.tasks.ExtendingTask;
import com.guardtime.ksi.util.Util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * KSI Extender Client which combines other clients to achieve redundancy.
 *
 * NB! It is highly recommended that all the extender configurations would be in sync with each other (except credentials).
 * If that is not the case then ExtenderHAClient will log a warning but it will still work.
 * If user asks for configuration from the ExtenderHAClient it will use the most conservative configuration of sub clients to
 * compose aggregated configuration.
 */
public class ExtenderHAClient extends AbstractHAClient<KSIExtenderClient, ExtensionResponse, ExtenderConfiguration> implements KSIExtenderClient {

    /**
     * Used to initialize ExtenderHAClient.
     *
     * @param extenderClients
     *          List of subclients to send the extending requests.
     *
     */
    public ExtenderHAClient(List<KSIExtenderClient> extenderClients) {
        super(extenderClients);
    }

    /**
     * Does a non-blocking extending request. Sends the request to all the subclients in parallel. First successful response is
     * used, others are cancelled. Request fails only if all the subclients fail.
     *
     * @see KSIExtenderClient#extend(Date, Date)
     */
    public Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(aggregationTime, "aggregationTime");
        Collection<KSIExtenderClient> clients = getSubclients();
        Collection<Callable<ExtensionResponse>> tasks = new ArrayList<Callable<ExtensionResponse>>(clients.size());
        for (KSIExtenderClient client : clients) {
            tasks.add(new ExtendingTask(client, aggregationTime, publicationTime));
        }
        return callAnyService(tasks);
    }

    /**
     * Used to get an aggregated configuration composed of subclients configurations.
     * Configuration requests are sent to all the subclients.
     *
     * @see HAExtenderConfiguration
     *
     * @return Aggregated extenders configuration.
     * @throws KSIException if all the subclients fail.
     */
    public ExtenderConfiguration getExtenderConfiguration() throws KSIException {
        Collection<Callable<SubclientConfiguration<ExtenderConfiguration>>> tasks = new ArrayList<Callable<SubclientConfiguration<ExtenderConfiguration>>>();
        for (KSIExtenderClient client : getSubclients()) {
            tasks.add(new ExtenderConfigurationTask(client));
        }
        return getConfiguration(tasks);
    }

    protected ExtenderConfiguration aggregateConfigurations(List<SubclientConfiguration<ExtenderConfiguration>> configurations) {
        return new HAExtenderConfiguration(configurations);
    }


    protected boolean configurationsEqual(ExtenderConfiguration c1, ExtenderConfiguration c2) {
        return Util.equals(c1.getMaximumRequests(), c2.getMaximumRequests()) &&
                Util.equals(c1.getCalendarFirstTime(), c2.getCalendarFirstTime()) &&
                Util.equals(c1.getCalendarLastTime(), c2.getCalendarLastTime()) &&
                Util.equalsIgnoreOrder(c1.getParents(), c2.getParents());
    }

    protected String configurationsToString(List<SubclientConfiguration<ExtenderConfiguration>> configurations) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < configurations.size(); i++) {
            SubclientConfiguration<ExtenderConfiguration> response = configurations.get(i);
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

    private String successResponseToString(String clientId, ExtenderConfiguration conf) {
        return  String.format("ExtenderConfiguration{" +
                "extenderId='%s'," +
                "maximumRequests='%s'," +
                "parents='%s'," +
                "calendarFirstTime='%s'," +
                "calendarLastTime='%s'" +
                "}",
                clientId,
                conf.getMaximumRequests(),
                conf.getParents(),
                conf.getCalendarFirstTime(),
                conf.getCalendarLastTime());
    }

    private String failedResponseToString(String clientId, Throwable t) {
        return String.format("successResponseToString{" +
                "extenderId='%s'," +
                "failureCause='%s'" +
                "}", clientId, Util.getStacktrace(t));
    }
}
