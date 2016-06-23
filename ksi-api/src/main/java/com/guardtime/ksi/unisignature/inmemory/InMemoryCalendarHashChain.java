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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.CalendarHashChainLink;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;

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
    private List<CalendarHashChainLink> chain = new LinkedList<CalendarHashChainLink>();

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

        this.registrationTime = new Date(calculateRegistrationTime() * 1000);
        this.outputHash = calculateCalendarHashChainHash();
    }

    public final DataHash calculateCalendarHashChainHash() throws InvalidCalendarHashChainException {
        DataHash input = inputHash;
        try {
            for (CalendarHashChainLink link : chain) {
                input = link.calculateChainStep(input);
            }
            return input;
        } catch (HashException e) {
            throw new InvalidCalendarHashChainException("Invalid calendar hash chain. " + e.getMessage(), e);
        }
    }

    /**
     * Calculates the time when the signature was registered in the KSI hash calendar. See the KSI specification chapter
     * 4.1.4 "Time Verification Algorithm".
     */
    long calculateRegistrationTime() throws InvalidCalendarHashChainException {
        long r = publicationTime.getTime() / 1000; // publication time in seconds
        long t = 0;
        // iterate over the chain in reverse
        ListIterator<CalendarHashChainLink> li = chain.listIterator(chain.size());
        while (li.hasPrevious()) {
            if (r <= 0) {
                throw new InvalidCalendarHashChainException("Calendar hash chain shape is inconsistent with publication time");
            }
            CalendarHashChainLink link = li.previous();

            if (!link.isRightLink()) {
                r = highBit(r) - 1;
            } else {
                t = t + highBit(r);
                r = r - highBit(r);
            }
        }

        if (r != 0) {
            throw new InvalidCalendarHashChainException("Calendar hash chain shape inconsistent with publication time");
        }

        return t;
    }

    /**
     * Returns the time when the signature was registered in the KSI hash calendar.
     * <p/>
     * For an internally consistent signature, this is the same as the value of the aggregation time field.
     *
     * @return the registration time.
     * @see #getAggregationTime()
     */
    public Date getRegistrationTime() {
        return registrationTime;
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
     * Returns the value of the highest 1-bit in r, which is also the highest integral power of 2 that is less than or
     * equal to r, or 2^floor(log2(r)).
     *
     * @param r
     *         input value
     * @return value of the highest 1-bit in r
     */
    private long highBit(long r) {
        return 1L << (63 - Long.numberOfLeadingZeros(r));
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
