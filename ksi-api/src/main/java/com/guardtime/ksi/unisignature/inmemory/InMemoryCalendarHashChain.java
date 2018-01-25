/*
 * Copyright 2013-2017 Guardtime, Inc.
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
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.CalendarHashChainLink;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * Calendar hash chains are represented by `calendar chain' structures that consist of: <ul> <li>index fields:
 * `publication time' and `aggregation time'; </li> <li>an `input hash': the input for the computation specified by the
 * hash chain;</li> <li>a sequence of `left link' and `right link' structures.</li> </ul>
 * <p/>
 * Each link field contains a hash value from the calendar hash tree.
 */
class InMemoryCalendarHashChain extends TLVStructure implements CalendarHashChain {

    private static final int ELEMENT_TYPE_PUBLICATION_TIME = 0x01;
    private static final int ELEMENT_TYPE_AGGREGATION_TIME = 0x02;
    private static final int ELEMENT_TYPE_INPUT_HASH = 0x05;

    private Date registrationTime;
    private DataHash outputHash;
    private Date publicationTime;
    private Date aggregationTime;
    private DataHash inputHash;
    private List<CalendarHashChainLink> chain = new LinkedList<>();

    public InMemoryCalendarHashChain(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_PUBLICATION_TIME:
                    this.publicationTime = readOnce(child).getDecodedDate();
                    continue;
                case ELEMENT_TYPE_AGGREGATION_TIME:
                    this.aggregationTime = readOnce(child).getDecodedDate();
                    continue;
                case ELEMENT_TYPE_INPUT_HASH:
                    this.inputHash = readOnce(child).getDecodedDataHash();
                    continue;
                case LeftInMemoryCalendarHashChainLink.ELEMENT_TYPE:
                    chain.add(new LeftInMemoryCalendarHashChainLink(child));
                    continue;
                case RightInMemoryCalendarHashChainLink.ELEMENT_TYPE:
                    chain.add(new RightInMemoryCalendarHashChainLink(child));
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        verifyConsistency();
    }

    public void verifyConsistency() throws InvalidCalendarHashChainException {
        if (publicationTime == null) {
            throw new InvalidCalendarHashChainException("Calendar hash chain publication time is missing");
        }
        if (inputHash == null) {
            throw new InvalidCalendarHashChainException("Calendar hash chain input hash is missing");
        }
        if (chain.isEmpty()) {
            throw new InvalidCalendarHashChainException("Calendar hash chain does not contain link elements");
        }

        this.outputHash = calculateCalendarHashChainHash();
    }

    public final DataHash calculateCalendarHashChainHash() throws InvalidCalendarHashChainException {
        DataHash input = inputHash;
        for (CalendarHashChainLink link : chain) {
            input = link.calculateChainStep(input);
        }
        return input;
    }

    /**
     * Returns the hash chain links. List is ordered.
     *
     * @return list of {@link CalendarHashChainLink} elements. always presents.
     */
    public List<CalendarHashChainLink> getChainLinks() {
        return chain;
    }

    /**
     * Returns the aggregation time, as written in the hash chain record.
     * <p/>
     * Note that while in an internally consistent signature this is the same as the signature registration time encoded
     * in the shape of the hash chain, we can't just assume the input data to be consistent.
     *
     * @return the aggregation time. always present.
     */
    public final Date getAggregationTime() {
        if (aggregationTime != null) {
            return aggregationTime;
        }
        // a missing aggregation time implies publication time as the default value
        return publicationTime;
    }

    /**
     * @return returns calendar hash chain input hash
     */
    public DataHash getInputHash() {
        return inputHash;
    }

    /**
     * @return returns publication data.
     */
    public PublicationData getPublicationData() throws KSIException {
        return new PublicationData(getPublicationTime(), getOutputHash());
    }

    /**
     * @return returns publication time
     */
    public Date getPublicationTime() {
        return publicationTime;
    }

    /**
     * @return returns calculated calendar hash chain output hash
     */
    public DataHash getOutputHash() {
        return outputHash;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

}
