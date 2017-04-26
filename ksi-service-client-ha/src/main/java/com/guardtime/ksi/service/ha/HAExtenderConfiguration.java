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

import static com.guardtime.ksi.service.ha.HAConfUtil.hasMoreContents;
import static com.guardtime.ksi.service.ha.HAConfUtil.isAfter;
import static com.guardtime.ksi.service.ha.HAConfUtil.isBefore;
import static com.guardtime.ksi.service.ha.HAConfUtil.isSmaller;

/**
 * Aggregated configuration based on multiple configurations and HAClient settings.
 */
class HAExtenderConfiguration implements ExtenderConfiguration {

    private Long maxRequests;
    private List<String> parents;
    private Date calFirstTime;
    private Date calLastTime;

    /**
     * @param confs
     *          All the configurations that were received from subclients
     */
    HAExtenderConfiguration(List<ExtenderConfiguration> confs) {
        for (ExtenderConfiguration conf : confs) {

            Long confMaxRequests = conf.getMaximumRequests();
            Date confCalFirstTime = conf.getCalendarFirstTime();
            Date confCalLastTime = conf.getCalendarLastTime();
            List<String> confParents = conf.getParents();

            if (isSmaller(maxRequests, confMaxRequests)) {
                maxRequests = confMaxRequests;
            }
            if (isAfter(calFirstTime, confCalFirstTime)) {
                calFirstTime = confCalFirstTime;
            }
            if (isBefore(calLastTime, confCalLastTime)) {
                calLastTime = confCalLastTime;
            }
            if (hasMoreContents(parents, confParents)) {
                parents = confParents;
            }
        }
    }

    /**
     * @return Smallest maxRequests of all subconfigurations.
     */
    public Long getMaximumRequests() {
        return maxRequests;
    }

    /**
     * @return Largest set of parents.
     */
    public List<String> getParents() {
        return parents;
    }

    /**
     * @return Latest calendarFirstTime of all the subconfigurations.
     */
    public Date getCalendarFirstTime() {
        return calFirstTime;
    }

    /**
     * @return Earliest calendarLastTime of all the subconfigurations.
     */
    public Date getCalendarLastTime() {
        return calLastTime;
    }
}
