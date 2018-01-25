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
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.CalendarAuthenticationRecord;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
import com.guardtime.ksi.unisignature.LinkMetadata;
import com.guardtime.ksi.unisignature.RFC3161Record;
import com.guardtime.ksi.unisignature.SignaturePublicationRecord;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class InMemoryKsiSignatureComponentFactory implements KSISignatureComponentFactory {

    public AggregationHashChain createAggregationHashChain(TLVElement element) throws KSIException {
        return new InMemoryAggregationHashChain(element);
    }

    public AggregationHashChain createAggregationHashChain(DataHash inputHash, Date aggregationTime, LinkedList<Long> indexes, LinkedList<AggregationChainLink> links, HashAlgorithm aggregationAlgorithm) throws KSIException {
        return new InMemoryAggregationHashChain(inputHash, aggregationTime, indexes, links, aggregationAlgorithm);
    }

    public CalendarAuthenticationRecord createCalendarAuthenticationRecord(TLVElement element) throws KSIException {
        return new InMemoryCalendarAuthenticationRecord(element);
    }

    public CalendarHashChain createCalendarHashChain(TLVElement element) throws KSIException {
        return new InMemoryCalendarHashChain(element);
    }

    public RFC3161Record createRFC3161Record(TLVElement element) throws KSIException {
        return new InMemoryRFC3161Record(element);
    }

    public SignaturePublicationRecord createPublicationRecord(TLVElement element) throws KSIException {
        return new InMemorySignaturePublicationRecord(element);
    }

    public SignaturePublicationRecord createPublicationRecord(PublicationData publicationData, List<String> publicationReferences, List<String> publicationRepositoryURIs) throws KSIException {
        return new InMemorySignaturePublicationRecord(publicationData, publicationReferences, publicationRepositoryURIs);
    }

    public AggregationChainLink createLeftAggregationChainLink(DataHash siblingHash, long levelCorrection) throws KSIException {
        return new LeftAggregationChainLink(siblingHash, levelCorrection);
    }

    public AggregationChainLink createLeftAggregationChainLink(AggregationChainLink link, long levelCorrection) throws KSIException {
        return new LeftAggregationChainLink(link, levelCorrection);
    }

    public AggregationChainLink createLeftAggregationChainLink(LinkMetadata metadata, long levelCorrection) throws KSIException {
        return new LeftAggregationChainLink(metadata, levelCorrection);
    }

    public AggregationChainLink createRightAggregationChainLink(DataHash siblingHash, long levelCorrection) throws KSIException {
        return new RightAggregationChainLink(siblingHash, levelCorrection);
    }

    public AggregationChainLink createRightAggregationChainLink(AggregationChainLink link, long levelCorrection) throws KSIException {
        return new RightAggregationChainLink(link, levelCorrection);
    }

    public AggregationChainLink createRightAggregationChainLink(LinkMetadata metadata, long levelCorrection) throws KSIException {
        return new RightAggregationChainLink(metadata, levelCorrection);
    }

    public LinkMetadata createLinkMetadata(String clientId, String machineId, Long sequenceNumber, Long requestTime) throws KSIException {
        return new InMemoryLinkMetadata(clientId, machineId, sequenceNumber, requestTime);
    }

}
