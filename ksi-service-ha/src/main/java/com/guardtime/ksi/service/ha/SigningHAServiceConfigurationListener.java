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

import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.service.KSISigningService;

import java.util.ArrayList;
import java.util.List;

/**
 * Handles configuration consolidation and listener updates for SigningHAService
 */
class SigningHAServiceConfigurationListener extends AbstractHAConfigurationListener<AggregatorConfiguration> {

    private final List<SubServiceConfListener<AggregatorConfiguration>> subServiceConfListeners = new ArrayList<SubServiceConfListener<AggregatorConfiguration>>();
    private final List<KSISigningService> subservices;

    public SigningHAServiceConfigurationListener(List<KSISigningService> subservices) {
        this.subservices = subservices;
        for (KSISigningService subservice : subservices) {
            SubServiceConfListener<AggregatorConfiguration> listener = new SubServiceConfListener<AggregatorConfiguration>(subservice.toString(), this);
            subservice.registerAggregatorConfigurationListener(listener);
            subServiceConfListeners.add(listener);
        }
    }

    protected AggregatorConfiguration consolidate(AggregatorConfiguration c1, AggregatorConfiguration c2) {
        boolean c1Exists = c1 != null;
        boolean c2Exists = c2 != null;
        if (c1Exists && c2Exists) {
            return new SigningHAServiceConfiguration(c1, c2);
        }
        if (c1Exists) {
            return new SigningHAServiceConfiguration(c1);
        }
        if (c2Exists) {
            return new SigningHAServiceConfiguration(c2);
        }
        return null;
    }

    List<SubServiceConfListener<AggregatorConfiguration>> getSubServiceConfListeners() {
        return subServiceConfListeners;
    }

    public void sendAggregationConfigurationRequest() {
        for (KSISigningService service : subservices) {
            service.sendAggregationConfigurationRequest();
        }
    }
}
