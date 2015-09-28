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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * KSI signature structure class. KSI signature consist of the following components: <ul> <li>Aggregation hash chain.
 * Represents the computation of the per-round root hash value from a document hash value</li> <li>Calendar hash chain.
 * Represents the computation of the published hash value from the per-round root hash value.</li> <li>Publication
 * record. Contains the published hash value and bibliographic references to the media where it appeared.</li>
 * <li>Authentication record. Contains the trace of authenticating a party (e.g. a key-based signature). There are two
 * types of authentication records: one for aggregation hash chains and another for calendar hash chains.</li> <li>Older
 * version (RFC3161) compatibility records </li> </ul>
 */
final class InMemoryKsiSignature extends TLVStructure implements KSISignature {

    public static final int ELEMENT_TYPE = 0x0800;
    private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryKsiSignature.class);
    private List<InMemoryAggregationHashChain> aggregationChains;
    private InMemoryCalendarHashChain calendarChain;
    private InMemorySignaturePublicationRecord publicationRecord;
    private InMemoryAggregationAuthenticationRecord aggregationAuthenticationRecord;
    private InMemoryCalendarAuthenticationRecord calendarAuthenticationRecord;
    private InMemoryRFC3161Record rfc3161Record;

    private String identity;

    public InMemoryKsiSignature(TLVElement element) throws KSIException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        List<InMemoryAggregationHashChain> aggregations = new ArrayList<InMemoryAggregationHashChain>();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case InMemoryAggregationHashChain.ELEMENT_TYPE:
                    aggregations.add(new InMemoryAggregationHashChain(child));
                    continue;
                case CalendarHashChain.ELEMENT_TYPE:
                    this.calendarChain = new InMemoryCalendarHashChain(readOnce(child));
                    continue;
                case SignaturePublicationRecord.ELEMENT_TYPE:
                    this.publicationRecord = new InMemorySignaturePublicationRecord(readOnce(child));
                    continue;
                case InMemoryAggregationAuthenticationRecord.ELEMENT_TYPE:
                    this.aggregationAuthenticationRecord = new InMemoryAggregationAuthenticationRecord(readOnce(child));
                    continue;
                case CalendarAuthenticationRecord.ELEMENT_TYPE:
                    this.calendarAuthenticationRecord = new InMemoryCalendarAuthenticationRecord(readOnce(child));
                    continue;
                case RFC3161Record.ELEMENT_TYPE:
                    this.rfc3161Record = new InMemoryRFC3161Record(readOnce(child));
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (aggregations.isEmpty()) {
            throw new InvalidSignatureException("At least one aggregation chain required");
        }
        if (calendarAuthenticationRecord != null && publicationRecord != null) {
            throw new InvalidSignatureException("Found calendar authentication record and publication record. Given elements can not coexist");
        }
        if (calendarChain == null && (calendarAuthenticationRecord != null || publicationRecord != null)) {
            throw new InvalidSignatureException("Found calendar authentication record without calendar hash chain");
        }
        this.aggregationChains = sortAggregationHashChains(aggregations);
        calculateCalendarHashChainOutput();
        this.identity = parseIdentity();
    }

    private String parseIdentity() throws KSIException {
        String identity = "";
        for (InMemoryAggregationHashChain chain : aggregationChains) {
            // get name
            String id = chain.getChainIdentity();
            if (id.length() > 0) {
                if (identity.length() > 0) {
                    identity += ".";
                }
                identity += id;
            }
        }
        return identity;
    }

    /**
     * This method is used to verify signature consistency.
     */
    private void calculateCalendarHashChainOutput() throws KSIException {
        ChainResult lastRes = null;
        for (InMemoryAggregationHashChain chain : aggregationChains) {
            if (lastRes == null) {
                lastRes = chain.calculateOutputHash(0L);
            } else {
                lastRes = chain.calculateOutputHash(lastRes.getLevel());
            }
            LOGGER.debug("Output hash of chain: {} is {}", chain, lastRes.getOutputHash());
        }
    }

    public final DataHash getInputHash() {
        return aggregationChains.get(0).getInputHash();
    }

    public InMemoryAggregationHashChain getLastAggregationHashChain() {
        return aggregationChains.get(aggregationChains.size() - 1);
    }

    public boolean isPublished() {
        return publicationRecord != null;
    }

    public String getIdentity() {
        return identity;
    }

    public Date getAggregationTime() {
        return calendarChain == null ? getLastAggregationHashChain().getAggregationTime() : calendarChain.getRegistrationTime();
    }

    public Date getRegistrationTime() {
        return calendarChain == null ? getLastAggregationHashChain().getAggregationTime() : calendarChain.getRegistrationTime();
    }

    public Date getPublicationTime() {
        return calendarChain != null ? calendarChain.getPublicationTime() : null;
    }

    public InMemoryAggregationHashChain[] getAggregationHashChains() {
        return aggregationChains.toArray(new InMemoryAggregationHashChain[aggregationChains.size()]);
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

    public InMemorySignaturePublicationRecord getPublicationRecord() {
        return publicationRecord;
    }

    public PublicationData getPublicationData() throws KSIException {
        return calendarChain.getPublicationData();
    }

    public CalendarAuthenticationRecord getCalendarAuthenticationRecord() {
        return calendarAuthenticationRecord;
    }

    public InMemoryCalendarHashChain getCalendarHashChain() {
        return calendarChain;
    }

    public InMemoryKsiSignature extend(CalendarHashChain calendar, PublicationRecord publicationsRecord) throws KSIException {
        InMemoryKsiSignature extendedSignature = new InMemoryKsiSignature(rootElement);
        InMemoryCalendarHashChain calendarHashChain = (InMemoryCalendarHashChain) calendar;
        if (calendarChain != null) {
            extendedSignature.getRootElement().replace(getCalendarHashChain().getRootElement(), calendarHashChain.getRootElement());
        } else {
            extendedSignature.getRootElement().addChildElement(calendarHashChain.getRootElement());
        }

        extendedSignature.calendarChain = calendarHashChain;

        if (extendedSignature.calendarAuthenticationRecord != null) {
            extendedSignature.getRootElement().remove(extendedSignature.calendarAuthenticationRecord.getRootElement());
            extendedSignature.calendarAuthenticationRecord = null;
        }

        if (publicationsRecord != null) {

            TLVStructure publicationRecord = (TLVStructure) publicationsRecord;
            publicationRecord.getRootElement().setType(SignaturePublicationRecord.ELEMENT_TYPE);
            InMemorySignaturePublicationRecord signaturePublicationRecord = new InMemorySignaturePublicationRecord(publicationRecord.getRootElement());
            if (extendedSignature.getPublicationRecord() != null) {
                extendedSignature.getRootElement().replace(extendedSignature.getPublicationRecord().getRootElement(), signaturePublicationRecord.getRootElement());

            } else {
                extendedSignature.getRootElement().addChildElement(publicationRecord.getRootElement());
            }
            extendedSignature.publicationRecord = signaturePublicationRecord;
        } else if (extendedSignature.getPublicationRecord() != null) {
            extendedSignature.getRootElement().remove(extendedSignature.getPublicationRecord().getRootElement());
            extendedSignature.publicationRecord = null;
        }
        return extendedSignature;
    }

    public RFC3161Record getRfc3161Record() {
        return rfc3161Record;
    }


    /**
     * Orders aggregation chains.
     *
     * @param chains
     *         aggregation chains to be ordered.
     * @return ordered list of aggregation chains
     */
    private List<InMemoryAggregationHashChain> sortAggregationHashChains(List<InMemoryAggregationHashChain> chains) throws InvalidSignatureException {
        Collections.sort(chains, new Comparator<InMemoryAggregationHashChain>() {
            public int compare(InMemoryAggregationHashChain chain1, InMemoryAggregationHashChain chain2) {
                return chain2.getChainIndex().size() - chain1.getChainIndex().size();
            }
        });

        Iterator<InMemoryAggregationHashChain> chainIterator = chains.iterator();
        InMemoryAggregationHashChain previousChain = null;
        InMemoryAggregationHashChain first = null;
        while (chainIterator.hasNext()) {
            InMemoryAggregationHashChain currentChain = chainIterator.next();
            if (first == null) {
                first = currentChain;
            }
            if (previousChain != null) {
                compareChains(previousChain, currentChain);
            }
            previousChain = currentChain;
        }

        return chains;
    }

    private void compareChains(InMemoryAggregationHashChain previousChain, InMemoryAggregationHashChain currentChain) throws InvalidSignatureException {
        List<Long> previousChainIndexes = previousChain.getChainIndex();
        List<Long> currentChainIndexes = currentChain.getChainIndex();

        // check size
        int previousChainSize = previousChainIndexes.size();
        if ((previousChainSize - 1) != currentChainIndexes.size()) {
            throw new InvalidSignatureException("Aggregation chain indexes are invalid. Invalid length");
        }
        // check that indexes are equal
        for (int i = 0; i < currentChainIndexes.size(); i++) {
            if (!currentChainIndexes.get(i).equals(previousChainIndexes.get(i))) {
                throw new InvalidSignatureException("Aggregation chain indexes are invalid. Invalid value. Expected " + previousChainIndexes.get(i) + ", got " + currentChainIndexes.get(i));
            }
        }
    }

}
