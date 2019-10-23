/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */
package com.guardtime.ksi.pdu;

import com.guardtime.ksi.pdu.v2.AggregatorPduV2Factory;
import com.guardtime.ksi.pdu.v2.ExtenderPduV2Factory;
import com.guardtime.ksi.pdu.v2.PduV2Factory;
import com.guardtime.ksi.service.ConfigurationListener;

import java.util.HashMap;
import java.util.Map;

public final class PduFactoryProvider {

    private static final Map<PduVersion, PduFactory> pduFactories = new HashMap<>();

    static {
        pduFactories.put(PduVersion.V2, new PduV2Factory());
    }

    public static PduFactory get(PduVersion pduVersion) {
        if (!pduFactories.containsKey(pduVersion)) {
            throw new IllegalArgumentException("Invalid PDU version '" + pduVersion + "'. Allowed values are: " + PduVersion.V2);
        }
        return pduFactories.get(pduVersion);
    }

    public static PduFactory withAggregatorConfListener(PduVersion pduVersion, ConfigurationListener<AggregatorConfiguration> aggregatorConfigurationListener) {
        return get(pduVersion, aggregatorConfigurationListener, null);
    }

    public static PduFactory withExtenderConfListener(PduVersion pduVersion, ConfigurationListener<ExtenderConfiguration> extenderConfigurationListener) {
        return get(pduVersion, null, extenderConfigurationListener);
    }

    private static PduFactory get(PduVersion pduVersion,
                                  ConfigurationListener<AggregatorConfiguration> aggregatorConfigurationListener,
                                  ConfigurationListener<ExtenderConfiguration> extenderConfigurationListener) {
         if (pduVersion == PduVersion.V2) {
            AggregatorPduV2Factory aggregatorPduV2Factory = new AggregatorPduV2Factory(aggregatorConfigurationListener);
            ExtenderPduV2Factory extenderPduV2Factory = new ExtenderPduV2Factory(extenderConfigurationListener);
            return new PduV2Factory(aggregatorPduV2Factory, extenderPduV2Factory);
        }
        throw new IllegalArgumentException("Invalid PDU version '" + pduVersion + "'. Allowed values are: " + PduVersion.V2);
    }
}
