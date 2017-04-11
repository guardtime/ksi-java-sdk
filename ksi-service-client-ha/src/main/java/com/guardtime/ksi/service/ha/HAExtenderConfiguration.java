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

class HAExtenderConfiguration implements ExtenderConfiguration {

    private final Long maximumRequests;
    private final List<String> parents;
    private final Date calendarFirstTime;
    private final Date calendarLastTime;

    HAExtenderConfiguration(List<ExtenderConfiguration> confs, int totalClients, int clientsInRound) {
        Long minMaxRequests = null;
        Date maxCalFirstTime = null;
        Date minCalLastTime = null;
        List<String> aggregatedParents = null;
        for (ExtenderConfiguration conf : confs) {
            Long confMaxRequests = conf.getMaximumRequests();
            Date confCalFirstTime = conf.getCalendarFirstTime();
            Date confCalLastTime = conf.getCalendarLastTime();
            if (minMaxRequests == null || (confMaxRequests != null && confMaxRequests <= minMaxRequests)) {
                minMaxRequests = confMaxRequests;
            }
            if (maxCalFirstTime == null || (confCalFirstTime != null && maxCalFirstTime.before
                    (confCalFirstTime))) {
                maxCalFirstTime = confCalFirstTime;
            }
            if (minCalLastTime == null || (confCalLastTime != null && minCalLastTime.after(confCalLastTime))) {
                minCalLastTime = confCalLastTime;
            }
            List<String> confParents = conf.getParents();
            if (aggregatedParents == null && confParents != null) {
                aggregatedParents = confParents;
            }
        }
        this.parents = aggregatedParents;
        this.maximumRequests = minMaxRequests == null ? null : (long) (minMaxRequests * (((double) totalClients) / clientsInRound));
        this.calendarFirstTime = maxCalFirstTime;
        this.calendarLastTime = minCalLastTime;
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
