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

package com.guardtime.ksi.unisignature;

import java.util.List;

import static com.guardtime.ksi.util.Util.notNull;

public final class AggregationHashChainUtil {

    /**
     * Calculates chain index
     *
     * @param links Chain links for which to calculate the index
     * @return Index of the chain
     */
    public static long calculateIndex(List<AggregationChainLink> links) {
        notNull(links, "Aggregation chain links");
        long chainIndex = 0;
        for (int i = 0; i < links.size(); i++) {
            if (links.get(i).isLeft()) {
                chainIndex |= 1L << i;
            }
        }
        chainIndex |= 1L << links.size();
        return chainIndex;
    }

    private AggregationHashChainUtil() {
    }
}
