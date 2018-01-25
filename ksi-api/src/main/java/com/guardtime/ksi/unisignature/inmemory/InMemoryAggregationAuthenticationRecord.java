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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.AggregationAuthenticationRecord;
import com.guardtime.ksi.unisignature.SignatureData;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * An aggregation authentication record is used to sign a hash value in an aggregation tree and corresponds to `left
 * link' structures in some aggregation hash chains.
 */
class InMemoryAggregationAuthenticationRecord extends TLVStructure implements AggregationAuthenticationRecord {

    private static final int ELEMENT_TYPE_AGGREGATION_TIME = 0x02;
    private static final int ELEMENT_TYPE_CHAIN_INDEX = 0x03;
    private static final int ELEMENT_TYPE_INPUT_HASH = 0x05;

    private Date aggregationTime;
    private List<Long> index = new LinkedList<>();
    private DataHash inputHash;
    private InMemorySignatureData signatureData;

    public InMemoryAggregationAuthenticationRecord(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_AGGREGATION_TIME:
                    this.aggregationTime = readOnce(child).getDecodedDate();
                    continue;
                case ELEMENT_TYPE_CHAIN_INDEX:
                    this.index.add(child.getDecodedLong());
                    continue;
                case ELEMENT_TYPE_INPUT_HASH:
                    this.inputHash = readOnce(child).getDecodedDataHash();
                    continue;
                case SignatureData.ELEMENT_TYPE:
                    this.signatureData = new InMemorySignatureData(readOnce(child));
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (aggregationTime == null) {
            throw new InvalidAggregationAuthenticationRecordException("Aggregation authentication record aggregation time can not be null");
        }
        if (inputHash == null) {
            throw new InvalidAggregationAuthenticationRecordException("Aggregation authentication record input hash can not be null");
        }
        if (signatureData == null) {
            throw new InvalidAggregationAuthenticationRecordException("Aggregation authentication record signature data can not be null");
        }

    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

}
