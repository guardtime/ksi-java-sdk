/*
 * Copyright 2013-2016 Guardtime, Inc.
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

package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.ArrayList;
import java.util.List;

/**
 * Aggregation configuration response payload element.
 */
public class AggregatorConfigurationPayload extends TLVStructure implements AggregatorConfiguration {

    private static final int TYPE_MAX_LEVEL = 0x01;
    private static final int TYPE_AGGREGATION_ALGORITHM = 0x02;
    private static final int TYPE_AGGREGATION_PERIOD = 0x03;
    private static final int TYPE_MAX_REQUESTS = 0x04;
    private static final int TYPE_PARENT_URI = 0x10;

    private Long maximumLevel;
    private HashAlgorithm aggregationAlgorithm;
    private Long aggregationPeriod;
    private Long maximumRequests;
    private List<String> parentUris = new ArrayList<String>();

    public AggregatorConfigurationPayload(TLVElement element) throws TLVParserException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case TYPE_MAX_LEVEL:
                    this.maximumLevel = readOnce(child).getDecodedLong();
                    continue;
                case TYPE_AGGREGATION_ALGORITHM:
                    this.aggregationAlgorithm = readOnce(child).getDecodedHashAlgorithm();
                    continue;
                case TYPE_AGGREGATION_PERIOD:
                    this.aggregationPeriod = readOnce(child).getDecodedLong();
                    continue;
                case TYPE_MAX_REQUESTS:
                    this.maximumRequests = readOnce(child).getDecodedLong();
                    continue;
                case TYPE_PARENT_URI:
                    parentUris.add(child.getDecodedString());
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
    }

    public Long getMaximumLevel() {
        return maximumLevel;
    }

    public HashAlgorithm getAggregationAlgorithm() {
        return aggregationAlgorithm;
    }

    public Long getAggregationPeriod() {
        return aggregationPeriod;
    }

    public Long getMaximumRequests() {
        return maximumRequests;
    }

    public List<String> getParents() {
        return parentUris;
    }

    public int getElementType() {
        return 0x04;
    }

    @Override
    public String toString() {
        return "AggregatorConfiguration{" +
                "maximumLevel=" + maximumLevel +
                ", aggregationAlgorithm=" + aggregationAlgorithm +
                ", aggregationPeriod=" + aggregationPeriod +
                ", maximumRequests=" + maximumRequests +
                ", parentUris=" + parentUris +
                '}';
    }
}
