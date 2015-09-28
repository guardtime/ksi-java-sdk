/*
 * Copyright 2013-2015 Guardtime, Inc.
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

package com.guardtime.ksi.multisignature.file;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Aggregation hash chain holder.
 */
final class AggregationHashChainHolder extends TlvStructureHolder<AggregationHashChainKey, AggregationHashChain> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AggregationHashChain.class);

    /**
     * Map for holding aggregation chain keys. Key is a dataHash and the value is aggregation hash chain key. Used to
     * find aggregation hash chains by document hash.
     */
    private Map<DataHash, AggregationHashChainKey> firstAggregationHashChains = null;

    @Override
    AggregationHashChainKey createKey(AggregationHashChain chain) {
        return new AggregationHashChainKey(chain.getAggregationTime(), chain.getChainIndex());
    }

    @Override
    String getTlvElementName() {
        return "aggregation hash chain";
    }


    /**
     * Adds multiple aggregation hash chains. If aggregation hash chain is present then the hash chain isn't added.
     *
     * @param aggregationChains
     *         list of aggregation hash chain to be added.
     */
    void add(AggregationHashChain[] aggregationChains) {
        for (AggregationHashChain chain : aggregationChains) {
            add(chain);
        }
        searchFirstAggregationHashChains();
    }

    List<AggregationHashChain> getAggregationHashChains(AggregationHashChainKey key) throws KSIException {
        LOGGER.info("Using aggregation hash chain key '{}' to build aggregation hash chain tree.", key);
        LinkedList<AggregationHashChainKey> nextKeys = key.getNextKeys();
        nextKeys.add(0, key);
        List<AggregationHashChain> chains = new LinkedList<AggregationHashChain>();
        for (AggregationHashChainKey nextKey : nextKeys) {
            AggregationHashChain aggregationChain = get(nextKey);
            chains.add(aggregationChain);
        }
        return chains;
    }

    Map<DataHash, AggregationHashChainKey> getFirstAggregationHashChains() {
        if (firstAggregationHashChains == null) {
            searchFirstAggregationHashChains();
        }
        return firstAggregationHashChains;
    }

    void searchFirstAggregationHashChains() {
        firstAggregationHashChains = new HashMap<DataHash, AggregationHashChainKey>();
        Set<AggregationHashChainKey> aggregationKeys = elementMap.keySet();
        for (AggregationHashChainKey key : aggregationKeys) {
            boolean firstChain = true;
            for (AggregationHashChainKey key2 : aggregationKeys) {
                if (key2.precedes(key)) {
                    firstChain = false;
                    break;
                }
            }
            if (firstChain) {
                AggregationHashChain chain = elementMap.get(key);
                LOGGER.info("Found first aggregation hash chain with input hash {}. Ky was '{}'", chain.getInputHash(), key);
                firstAggregationHashChains.put(chain.getInputHash(), key);
            }
        }
    }

    public AggregationHashChainKey get(DataHash documentHash) {
        return getFirstAggregationHashChains().get(documentHash);
    }

}
