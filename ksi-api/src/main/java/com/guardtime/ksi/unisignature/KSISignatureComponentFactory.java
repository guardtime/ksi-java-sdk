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

package com.guardtime.ksi.unisignature;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.tlv.TLVElement;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * An interface for creating components of KSI signatures like aggregation chains and calendar authentication records.
 */
public interface KSISignatureComponentFactory {

    /**
     * Creates an aggregation hash chain from input TLV element.
     *
     * @param element instance of {@link TLVElement}. not null
     * @return instance of {@link AggregationHashChain}
     * @throws KSIException
     */
    AggregationHashChain createAggregationHashChain(TLVElement element) throws KSIException;

    /**
     * Creates a new aggregation hash chain
     */
    AggregationHashChain createAggregationHashChain(DataHash inputHash, Date aggregationTime, LinkedList<Long> indexes, LinkedList<AggregationChainLink> links, HashAlgorithm aggregationAlgorithm) throws KSIException;

    /**
     * Creates a new left aggregation hash chain link with given sibling hash and level.
     */
    AggregationChainLink createLeftAggregationChainLink(DataHash siblingHash, long level) throws KSIException;

    /**
     * Creates a new left aggregation hash chain link with corresponding data of given link and level.
     */
    AggregationChainLink createLeftAggregationChainLink(AggregationChainLink link, long levelCorrection) throws KSIException;

    /**
     * Creates a new left aggregation hash chain link with given metadata and level.
     */
    AggregationChainLink createLeftAggregationChainLink(LinkMetadata identity, long level) throws KSIException;

    /**
     * Creates a new right aggregation hash chain link with given sibling hash and level.
     */
    AggregationChainLink createRightAggregationChainLink(DataHash siblingHash, long level) throws KSIException;

    /**
     * Creates a new right aggregation hash chain link with given metadata and level.
     */
    AggregationChainLink createRightAggregationChainLink(LinkMetadata identity, long level) throws KSIException;

    /**
     * Creates a new right aggregation hash chain link with corresponding data of given link and level.
     */
    AggregationChainLink createRightAggregationChainLink(AggregationChainLink link, long levelCorrection) throws KSIException;

    /**
     * Creates calendar authentication record from input TLV element.
     *
     * @param element instance of {@link TLVElement}. not null
     * @return instance of {@link CalendarAuthenticationRecord}
     * @throws KSIException when error occurs (e.g input data is invalid)
     */
    CalendarAuthenticationRecord createCalendarAuthenticationRecord(TLVElement element) throws KSIException;

    /**
     * Creates calendar hash chain from input TLV element.
     *
     * @param element instance of {@link TLVElement}. not null
     * @return instance of {@link CalendarHashChain}
     * @throws KSIException when error occurs (e.g input data is invalid)
     */
    CalendarHashChain createCalendarHashChain(TLVElement element) throws KSIException;

    /**
     * Creates RFC3161 record element from input TLV element.
     *
     * @param element instance of {@link TLVElement}. not null
     * @return instance of {@link RFC3161Record}
     * @throws KSIException when error occurs (e.g input data is invalid)
     */
    RFC3161Record createRFC3161Record(TLVElement element) throws KSIException;

    /**
     * Creates signature publication record element from input TLV element.
     *
     * @param element instance of {@link TLVElement}. not null
     * @return instance of {@link SignaturePublicationRecord}
     * @throws KSIException when error occurs (e.g input data is invalid)
     */
    SignaturePublicationRecord createPublicationRecord(TLVElement element) throws KSIException;

    /**
     * Creates a signature publication record element from publication data, publication references and publication repository URI's
     */
    SignaturePublicationRecord createPublicationRecord(PublicationData publicationData, List<String> publicationReferences, List<String> publicationRepositoryURIs) throws KSIException;

    /**
     * Creates a link metadata structure.
     */
    LinkMetadata createLinkMetadata(String clientId, String machineId, Long sequenceNumber, Long requestTime) throws KSIException;
}
