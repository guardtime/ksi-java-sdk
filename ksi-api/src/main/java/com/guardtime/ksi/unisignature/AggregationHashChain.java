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

package com.guardtime.ksi.unisignature;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;

import java.util.Date;
import java.util.List;

/**
 * An aggregation hash chain that represents (a part of) the computation of the per-round global root hash value from a
 * document hash value. Aggregation hash chain contains the following data: <ul> <li>index fields: an `aggregation time'
 * and a sequence of `chain index' values;</li> <li>an `input hash' and an optional `input data': the input for the
 * computation specified by the hash chain;</li> <li>`aggregation algorithm': the one-byte identifier of the hash
 * function used to compute the output hash values of the link structures</li> <li>a sequence of `left link' and `right
 * link' structures</li> </ul>
 */
public interface AggregationHashChain {

    int ELEMENT_TYPE = 0x0801;

    /**
     * Returns the aggregation time.
     */
    Date getAggregationTime();

    /**
     * Returns the chain index of the aggregation chain.
     */
    List<Long> getChainIndex();

    /**
     * Returns the input hash for the computation specified by the aggregation hash chain
     */
    DataHash getInputHash();

    /**
     * Returns the output hash
     */
    DataHash getOutputHash();

    /**
     * Returns the list of aggregation chain left and right links. List must always be ordered.
     */
    List<AggregationChainLink> getChainLinks();

    /**
     * Returns the chain identity.
     *
     * @throws KSIException
     *         when identity calculation fails
     */
    String getChainIdentity(String separator) throws KSIException;

    /**
     * Calculates the aggregation hash chain ouput hash.
     */
    ChainResult calculateOutputHash(long level) throws KSIException;
}
