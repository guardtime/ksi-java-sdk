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

package com.guardtime.ksi.multisignature.file;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.multisignature.KSIMultiSignature;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.ExtensionRequestFuture;
import com.guardtime.ksi.service.KSIService;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * <p>File based in memory multi signature implementation. TLV encoding is used to save file. <p/> In memory
 * multi-signature file has the following components: <ul> <li>8-byte magic bytes which encodes the string 'MULTISIG' in
 * ASCII</li> <li>list of aggregation chains</li> <li>list of calendar hash chains</li> <li>list of calendar chain
 * authentication records</li> <li>list of aggregation chain authentication records </li> <li>list of RFC3161
 * compatibility records</li> </ul> <p/> <p>NB! The TLV elements inside multi signature can be in any order. When saving
 * the multi signature to the file then the order of the TLV elements may be changed.</p> <p>NB! If keyless
 * uni-signature contains unknown elements then the unknown elements will not be added to the multi signature.</p>
 */
final class FileBasedMultiSignature implements KSIMultiSignature {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileBasedMultiSignature.class);

    /**
     * In-memory based multi signature magic bytes
     */
    static final byte[] MAGIC_BYTES = new byte[]{'M', 'U', 'L', 'T', 'I', 'S', 'I', 'G'};

    private final AggregationHashChainHolder aggregationHashChains = new AggregationHashChainHolder();
    private final CalendarHashChainHolder calendarHashChains = new CalendarHashChainHolder();
    private final CalendarAuthenticationRecordHolder calendarAuthenticationRecords = new CalendarAuthenticationRecordHolder();
    private final SignaturePublicationRecordHolder signaturePublicationRecords = new SignaturePublicationRecordHolder();
    private final RFC3161RecordHolder rfc3161Records = new RFC3161RecordHolder();
    private final FileBasedMultiSignatureFactory.FileBasedMultiSignatureWriter writer;

    private final KSISignatureFactory uniSignatureFactory;
    private final KSIService ksiService;

    FileBasedMultiSignature(FileBasedMultiSignatureFactory.FileBasedMultiSignatureWriter writer, KSIService ksiService, KSISignatureFactory uniSignatureFactory) {
        this.writer = writer;
        this.ksiService = ksiService;
        this.uniSignatureFactory = uniSignatureFactory;
    }

    FileBasedMultiSignature(InputStream input, FileBasedMultiSignatureFactory.FileBasedMultiSignatureWriter writer, KSIService ksiService, KSISignatureFactory uniSignatureFactory) throws KSIException {
        this(writer, ksiService, uniSignatureFactory);
        TLVInputStream tlvInputStream = new TLVInputStream(input);
        verifyMagicBytes(tlvInputStream);
        try {
            parse(tlvInputStream);
        } catch (IOException e) {
            throw new KSIException("Reading multi signature container failed", e);
        }
    }

    /**
     * Adds uni-signature to the container.
     *
     * @param signature
     *         uni-signature to be added to the container
     * @throws KSIException
     */
    public void add(KSISignature signature) throws KSIException {
        if (signature == null) {
            throw new KSIException("Input signature can not be null");
        }
        aggregationHashChains.add(signature.getAggregationHashChains());
        CalendarHashChain presentCalendarHashChain = calendarHashChains.get(signature.getAggregationTime());
        if (presentCalendarHashChain != null && presentCalendarHashChain.getPublicationTime().before(signature.getPublicationTime())) {
            Date presentCalendarHashChainPublicationTime = presentCalendarHashChain.getPublicationTime();
            signaturePublicationRecords.remove(signaturePublicationRecords.get(presentCalendarHashChainPublicationTime));
            calendarAuthenticationRecords.remove(calendarAuthenticationRecords.get(presentCalendarHashChainPublicationTime));
            calendarHashChains.remove(presentCalendarHashChain);
        }
        calendarHashChains.add(signature.getCalendarHashChain());
        signaturePublicationRecords.add(signature.getPublicationRecord());
        calendarAuthenticationRecords.add(signature.getCalendarAuthenticationRecord());
        rfc3161Records.add(signature.getRfc3161Record());
        writer.write(this);
    }

    public KSISignature get(DataHash documentHash) throws KSIException {
        LOGGER.info("Searching uni-signature for hash '{}'", documentHash);
        if (documentHash == null) {
            throw new KSIException("Invalid input. Document hash is null");
        }
        DataHash dataHash = documentHash;

        RFC3161Record rfc3161Record = rfc3161Records.get(dataHash);
        if (rfc3161Record != null) {
            HashAlgorithm[] usedHashAlgorithms = getUsedHashAlgorithms();
            LOGGER.info("Found RFC3161 record. Starting to calculate rfc3161 record output hash. Algorithms to check {}", usedHashAlgorithms);
            for (HashAlgorithm algorithm : usedHashAlgorithms) {
                DataHash result = rfc3161Record.getOutputHash(algorithm);
                LOGGER.debug("Calculated RFC3161 record output hash using algorithm {} and input hash {}", algorithm, rfc3161Record.getInputHash());
                if (aggregationHashChains.get(result) != null) {
                    dataHash = result;
                    break;
                }
            }
        }

        AggregationHashChainKey aggregationHashChainKey = aggregationHashChains.get(dataHash);
        if (aggregationHashChainKey == null) {
            throw new KSIException("Signature not found for hash " + documentHash);
        }
        LOGGER.info("Found aggregation hash chain key '{}' for first aggregation chain. Starting to build aggregation hash chains.", aggregationHashChainKey);
        List<AggregationHashChain> chains = aggregationHashChains.getAggregationHashChains(aggregationHashChainKey);
        AggregationHashChain lastAggregationHashChain = chains.get(chains.size() - 1);
        CalendarHashChain calendarChain = calendarHashChains.get(lastAggregationHashChain.getAggregationTime());
        PublicationRecord signaturePublicationRecord = signaturePublicationRecords.get(calendarChain.getPublicationTime());
        CalendarAuthenticationRecord calendarAuthenticationRecord = calendarAuthenticationRecords.get(calendarChain.getPublicationTime());
        return uniSignatureFactory.createSignature(chains, calendarChain, calendarAuthenticationRecord, signaturePublicationRecord, rfc3161Record);
    }

    public void remove(DataHash dataHash) throws KSIException {
        if (dataHash == null) {
            throw new KSIException("Invalid input. Data hash is null");
        }
        KSISignature signature = get(dataHash);
        final AggregationHashChain[] aggregationChains = signature.getAggregationHashChains();
        final CalendarHashChain calendarHashChain = signature.getCalendarHashChain();
        final CalendarAuthenticationRecord calendarAuthenticationRecord = signature.getCalendarAuthenticationRecord();
        final PublicationRecord publicationRecord = signature.getPublicationRecord();
        RFC3161Record rfc3161Record = signature.getRfc3161Record();
        rfc3161Records.remove(rfc3161Record);
        for (AggregationHashChain chain : aggregationChains) {
            final AggregationHashChainKey aggregationKey = new AggregationHashChainKey(chain.getAggregationTime(), chain.getChainIndex());
            remove((TLVStructure) chain, new AggregationChainReferenceChecker(aggregationKey), aggregationHashChains, aggregationHashChains);
        }
        if (calendarHashChain != null) {
            final PublicationData publicationDataKey = new PublicationData(calendarHashChain.getAggregationTime(), calendarHashChain.getInputHash());
            remove((TLVStructure) calendarHashChain, new CalendarChainReferenceChecker(publicationDataKey), aggregationHashChains, calendarHashChains);
            if (publicationRecord != null) {
                remove((TLVStructure) publicationRecord, new SignaturePublicationRecordReferenceChecker(publicationRecord.getPublicationData()), calendarHashChains, signaturePublicationRecords);
            }
            if (calendarAuthenticationRecord != null) {
                remove((TLVStructure) calendarAuthenticationRecord, new CalendarAuthenticationRecordReferenceChecker(calendarAuthenticationRecord.getPublicationData()), calendarHashChains, calendarAuthenticationRecords);
            }
        }
        aggregationHashChains.searchFirstAggregationHashChains();
        writer.write(this);
    }

    /**
     * This method returns the hash algorithms that is used by uni-signatures inside this container.
     *
     * @return list of hash algorithms.
     */
    public HashAlgorithm[] getUsedHashAlgorithms() {
        Set<DataHash> keys = aggregationHashChains.getFirstAggregationHashChains().keySet();
        Set<HashAlgorithm> algorithms = EnumSet.noneOf(HashAlgorithm.class);
        for (DataHash key : keys) {
            HashAlgorithm algorithm = key.getAlgorithm();
            if (!algorithms.contains(algorithm)) {
                algorithms.add(algorithm);
            }
        }
        Collection<RFC3161Record> rfc3161s = rfc3161Records.get();
        for (RFC3161Record rfc3161 : rfc3161s) {
            HashAlgorithm algorithm = rfc3161.getInputHash().getAlgorithm();
            if (!algorithms.contains(algorithm)) {
                algorithms.add(algorithm);
            }
        }
        return algorithms.toArray(new HashAlgorithm[algorithms.size()]);
    }

    /**
     * <p>When called, all unextended signatures are extended to the closest (oldest) publication possible. If there is
     * no suitable publication to extend one signature - that signature will not be extended.</p>
     */
    public void extend(PublicationsFile trustStore) throws KSIException {
        if (trustStore == null) {
            throw new KSIException("Invalid input parameter. KSI trust store is missing.");
        }
        Collection<AggregationHashChainKey> aggregationHashChainKeys = getFirstAggregationHashChains();
        Map<KSISignature, ExtensionRequestFuture> futures = new LinkedHashMap<KSISignature, ExtensionRequestFuture>();
        Map<KSISignature, PublicationRecord> publications = new LinkedHashMap<KSISignature, PublicationRecord>();
        Map<PublicationRecord, ExtensionRequestFuture> requests = new HashMap<PublicationRecord, ExtensionRequestFuture>();
        for (AggregationHashChainKey key : aggregationHashChainKeys) {
            AggregationHashChain chain = aggregationHashChains.get(key);
            DataHash inputHash = chain.getInputHash();
            KSISignature signature = get(inputHash);
            PublicationRecord publicationRecord = trustStore.getPublicationRecord(signature.getAggregationTime());
            if (publicationRecord == null) {
                continue;
            }
            Date publicationTime = publicationRecord.getPublicationData().getPublicationTime();
            if (signature.getPublicationRecord() == null) {
                if (!requests.containsKey(publicationRecord)) {
                    publications.put(signature, publicationRecord);
                    LOGGER.info("Sending extension request. Aggregation time is {}, publication time is {}", signature.getAggregationTime(), publicationTime);
                    ExtensionRequestFuture future = ksiService.extend(signature.getAggregationTime(), publicationTime);
                    futures.put(signature, future);
                    requests.put(publicationRecord, future);
                } else {
                    LOGGER.info("Found already sent extension request. Aggregation time is {}, publication time is {}", signature.getAggregationTime(), publicationTime);
                    futures.put(signature, requests.get(publicationRecord));
                }
            }
        }
        LOGGER.info("Sent {} extension requests.", futures.size());
        for (KSISignature signature : futures.keySet()) {
            ExtensionRequestFuture requestFuture = futures.get(signature);
            CalendarHashChain extendedCalendarHashChain = requestFuture.getResult();
            remove(signature.getInputHash());
            KSISignature extendedSignature = signature.extend(extendedCalendarHashChain, publications.get(signature));
            add(extendedSignature);
        }
        writer.write(this);

    }

    /**
     * <p> When called all (inc already extended) signatures are extended to a specific publication. Signature isn't
     * extended if a signature is a newer than the given publication. <p/>
     */
    public void extend(com.guardtime.ksi.publication.PublicationRecord publicationRecord) throws KSIException {
        if (publicationRecord == null) {
            throw new KSIException("Invalid input parameter. Publication record is missing.");
        }
        Collection<AggregationHashChainKey> aggregationHashChainKeys = getFirstAggregationHashChains();
        Map<KSISignature, ExtensionRequestFuture> futures = new LinkedHashMap<KSISignature, ExtensionRequestFuture>();
        Map<Date, ExtensionRequestFuture> requests = new HashMap<Date, ExtensionRequestFuture>();
        for (AggregationHashChainKey key : aggregationHashChainKeys) {
            AggregationHashChain chain = aggregationHashChains.get(key);
            DataHash inputHash = chain.getInputHash();
            KSISignature signature = get(inputHash);
            Date aggregationTime = signature.getAggregationTime();
            Date publicationTime = publicationRecord.getPublicationData().getPublicationTime();
            if (aggregationTime.before(publicationTime)) {
                if (!requests.containsKey(aggregationTime)) {
                    LOGGER.info("Sending extension request. Aggregation time is {}, publication time is {}", aggregationTime, publicationTime);
                    ExtensionRequestFuture future = ksiService.extend(aggregationTime, publicationTime);
                    futures.put(signature, future);
                    requests.put(aggregationTime, future);
                } else {
                    LOGGER.info("Found already sent extension request. Aggregation time is {}, publication time is {}", aggregationTime, publicationTime);
                    futures.put(signature, requests.get(aggregationTime));
                }
            }
        }
        LOGGER.info("Sent {} extension requests.", requests.size());
        for (KSISignature signature : futures.keySet()) {
            ExtensionRequestFuture requestFuture = futures.get(signature);
            CalendarHashChain extendedCalendarHashChain = requestFuture.getResult();
            remove(signature.getInputHash());
            KSISignature extendedSignature = signature.extend(extendedCalendarHashChain, publicationRecord);
            add(extendedSignature);
        }
        writer.write(this);
    }

    /**
     * Returns the list of aggregation chains inside multi signature.
     */
    Collection<AggregationHashChain> getAggregationHashChains() {
        return aggregationHashChains.get();
    }

    /**
     * Returns the list of the first aggregation chain keys.
     */
    Collection<AggregationHashChainKey> getFirstAggregationHashChains() {
        return aggregationHashChains.getFirstAggregationHashChains().values();
    }

    /**
     * Returns the collection of aggregation hash chains inside the multi signature
     */
    Collection<CalendarHashChain> getCalendarHashChains() {
        return calendarHashChains.get();
    }

    /**
     * Returns the list of calendar authentication records inside the multi signature.
     */
    Collection<CalendarAuthenticationRecord> getCalendarAuthenticationRecords() {
        return calendarAuthenticationRecords.get();
    }

    /**
     * Returns the list of uni-signature publication records inside the multi signature.
     */
    Collection<PublicationRecord> getSignaturePublicationRecords() {
        return signaturePublicationRecords.get();
    }

    /**
     * Returns the list of uni-signature RFC3161 records inside the multi signature.
     */
    Collection<RFC3161Record> getRfc3161Records() {
        return rfc3161Records.get();
    }

    /**
     * Verifies that input stream starts with in-memory multi signature magic bytes.
     *
     * @param input
     *         instance of input stream to check. not null.
     */
    private void verifyMagicBytes(TLVInputStream input) throws InvalidFileBasedMultiSignatureException {
        try {
            byte[] magicBytes = new byte[MAGIC_BYTES.length];
            input.read(magicBytes);
            if (!Arrays.equals(magicBytes, MAGIC_BYTES)) {
                throw new InvalidFileBasedMultiSignatureException("Invalid publications file magic bytes");
            }
        } catch (IOException e) {
            throw new InvalidFileBasedMultiSignatureException("Checking publications file magic bytes failed", e);
        }
    }

    private void remove(TLVStructure tlvToDelete, ReferenceChecker checker, TlvStructureHolder readFrom, TlvStructureHolder deleteStructure) throws KSIException {
        int count = 0;
        if (tlvToDelete != null) {
            count = readFrom.count(checker);
            LOGGER.info("TLV element {} with key {} is referred by {} {}s", deleteStructure.getTlvElementName(), deleteStructure.createKey(tlvToDelete), count, readFrom.getTlvElementName());
        }
        if (count < 1) {
            deleteStructure.remove(tlvToDelete);
        }
    }

    private void parse(TLVInputStream tlvInputStream) throws IOException, KSIException {
        while (tlvInputStream.hasNextElement()) {
            TLVElement element = tlvInputStream.readElement();
            switch (element.getType()) {
                case AggregationHashChain.ELEMENT_TYPE:
                    aggregationHashChains.add(uniSignatureFactory.createAggregationHashChain(element));
                    break;
                case CalendarHashChain.ELEMENT_TYPE:
                    calendarHashChains.add(uniSignatureFactory.createCalendarHashChain(element));
                    break;
                case CalendarAuthenticationRecord.ELEMENT_TYPE:
                    calendarAuthenticationRecords.add(uniSignatureFactory.createCalendarAuthenticationRecord(element));
                    break;
                case SignaturePublicationRecord.ELEMENT_TYPE:
                    signaturePublicationRecords.add(uniSignatureFactory.createPublicationRecord(element));
                    break;
                case RFC3161Record.ELEMENT_TYPE:
                    rfc3161Records.add(uniSignatureFactory.createRFC3161Record(element));
                    break;
                default:
                    LOGGER.info("Multi signature container contains unknown element: {} ", element);
            }
        }
    }

}
