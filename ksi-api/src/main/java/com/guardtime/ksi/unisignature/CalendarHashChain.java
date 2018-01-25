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

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.tlv.GlobalTlvTypes;

import java.util.Date;
import java.util.List;

/**
 * Calendar hash chains are represented by `calendar chain' structures that consist of: <ul> <li>index fields:
 * `publication time' and `aggregation time'; </li> <li>an `input hash': the input for the computation specified by the
 * hash chain;</li> <li>a sequence of `left link' and `right link' structures.</li> </ul>
 * <p/>
 * Each link field contains a hash value from the calendar hash tree.
 */
public interface CalendarHashChain {

    int ELEMENT_TYPE = GlobalTlvTypes.ELEMENT_TYPE_CALENDAR_HASH_CHAIN;

    /**
     * Returns the input hash of the calendar hash chain
     */
    DataHash getInputHash();

    /**
     * Returns the output hash of the calendar hash chain
     */
    DataHash getOutputHash();

    /**
     * Returns the aggregation time, as written in the hash chain record.
     * <p/>
     * Note that while in an internally consistent signature this is the same as the signature registration time encoded
     * in the shape of the hash chain, we can't just assume the input data to be consistent.
     *
     * @return the aggregation time. always present.
     */
    Date getAggregationTime();

    /**
     * Returns the publication time of the calendar hash chain
     */
    Date getPublicationTime();

    /**
     * Returns the left and right chain links
     */
    List<CalendarHashChainLink> getChainLinks();

}
