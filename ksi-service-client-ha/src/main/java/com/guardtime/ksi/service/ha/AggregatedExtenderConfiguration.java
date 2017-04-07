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

import com.guardtime.ksi.pdu.ExtenderConfiguration;

import java.util.Date;
import java.util.List;

class AggregatedExtenderConfiguration implements ExtenderConfiguration {

    private final Long maximumRequests;
    private final List<String> parents;
    private final Date calendarFirstTime;
    private final Date calendarLastTime;

    AggregatedExtenderConfiguration(List<ExtenderConfiguration> subConfigurations, int totalNumberOfClients, int numberOfClientsInOneRound) {
        Long minMaximumRequests = null;
        Date maxCalendarFirstTime = null;
        Date minCalendarLastTime = null;
        List<String> aggregatedParents = null;
        for (ExtenderConfiguration subConfiguration : subConfigurations) {
            Long subConfMaxRequests = subConfiguration.getMaximumRequests();
            Date subConfCalendarFirstTime = subConfiguration.getCalendarFirstTime();
            Date subConfCalendarLastTime = subConfiguration.getCalendarLastTime();
            if (minMaximumRequests == null || (subConfMaxRequests != null && subConfMaxRequests <= minMaximumRequests)) {
                minMaximumRequests = subConfMaxRequests;
            }
            if (maxCalendarFirstTime == null || (subConfCalendarFirstTime != null && maxCalendarFirstTime.before
                    (subConfCalendarFirstTime))) {
                maxCalendarFirstTime = subConfCalendarFirstTime;
            }
            if (minCalendarLastTime == null || (subConfCalendarLastTime != null && minCalendarLastTime.after(subConfCalendarLastTime))) {
                minCalendarLastTime = subConfCalendarLastTime;
            }
            List<String> subConfParents = subConfiguration.getParents();
            if (aggregatedParents == null && subConfParents != null) {
                aggregatedParents = subConfParents;
            }
        }
        this.parents = aggregatedParents;
        this.maximumRequests = minMaximumRequests == null ? null : (long) (minMaximumRequests * (((double) totalNumberOfClients) / numberOfClientsInOneRound));
        this.calendarFirstTime = maxCalendarFirstTime;
        this.calendarLastTime = minCalendarLastTime;
    }

    public Long getMaximumRequests() {
        return maximumRequests;
    }

    public List<String> getParents() {
        return parents;
    }

    public Date getCalendarFirstTime() {
        return calendarFirstTime;
    }

    public Date getCalendarLastTime() {
        return calendarLastTime;
    }
}
