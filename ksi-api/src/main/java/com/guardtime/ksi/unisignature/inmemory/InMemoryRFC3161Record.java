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
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.RFC3161Record;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * An older implementation of the KSI service used the formats and protocols specified in the X.509 time-stamping
 * standard (RFC 3161). In that format, the hash value of the time-stamped datum was not signed directly, but via
 * several intermediate structures.
 * <p/>
 * To facilitate conversion of legacy KSI signatures issued in the RFC 3161 format, the helper data structure is used,
 * whit the following fields <ul> <li>The `aggregation time', `chain index' and `input hash' fields have the same
 * meaning as in the `aggregation chain' structure defined in Section 4.1.1.</li><li> The `tstinfo prefix' and `tstinfo
 * suffix' fields contain the data preceding and succeeding the hash value within the TSTInfo structure.</li><li> The
 * `tstinfo algorithm' field contains the one-byte identifier (as defined in Table 2) of the hash function used to hash
 * the TSTInfo structure.</li><li> The `signed attributes prefix' and `signed attributes suffix' fields contain the data
 * preceding and succeeding the hash value within the SignedAttributes structure.</li><li> The `signed attributes
 * algorithm' field contains the one-byte identifier of the hash function used to hash the SignedAttributes
 * structure.</li> </ul>
 */
class InMemoryRFC3161Record extends TLVStructure implements RFC3161Record {

    private static final int ELEMENT_TYPE_AGGREGATION_TIME = 0x02;
    private static final int ELEMENT_TYPE_CHAIN_INDEX = 0x03;
    private static final byte ELEMENT_TYPE_INPUT_HASH = 0x05;
    private static final int ELEMENT_TYPE_TST_INFO_PREFIX = 0x10;
    private static final int ELEMENT_TYPE_TST_INFO_SUFFIX = 0x11;
    private static final int ELEMENT_TYPE_TST_INFO_ALGORITHM = 0x12;
    private static final int ELEMENT_TYPE_SIGNATURE_ATTRIBUTE_PREFIX = 0x13;
    private static final int ELEMENT_TYPE_SIGNATURE_ATTRIBUTE_SUFFIX = 0x14;
    private static final int ELEMENT_TYPE_SIGNATURE_ATTRIBUTE_ALGORITHM = 0x15;

    private Date aggregationTime;

    private List<Long> chainIndex = new LinkedList<>();

    private DataHash inputHash;

    private byte[] tstInfoPrefix;

    private byte[] tstInfoSuffix;

    private Long tstInfoAlgorithm;

    private byte[] signedAttributesPrefix;

    private byte[] signedAttributesSuffix;

    private Long signedAttributesAlgorithm;

    /**
     * Creates new RFC3161 record element
     *
     * @param rootElement
     *         TLV element used to createSignature RFC3161 record
     */
    public InMemoryRFC3161Record(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_AGGREGATION_TIME:
                    this.aggregationTime = readOnce(child).getDecodedDate();
                    continue;
                case ELEMENT_TYPE_CHAIN_INDEX:
                    chainIndex.add(child.getDecodedLong());
                    continue;
                case ELEMENT_TYPE_INPUT_HASH:
                    this.inputHash = readOnce(child).getDecodedDataHash();
                    continue;
                case ELEMENT_TYPE_TST_INFO_PREFIX:
                    this.tstInfoPrefix = readOnce(child).getContent();
                    continue;
                case ELEMENT_TYPE_TST_INFO_SUFFIX:
                    this.tstInfoSuffix = readOnce(child).getContent();
                    continue;
                case ELEMENT_TYPE_TST_INFO_ALGORITHM:
                    this.tstInfoAlgorithm = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_SIGNATURE_ATTRIBUTE_PREFIX:
                    this.signedAttributesPrefix = readOnce(child).getContent();
                    continue;
                case ELEMENT_TYPE_SIGNATURE_ATTRIBUTE_SUFFIX:
                    this.signedAttributesSuffix = readOnce(child).getContent();
                    continue;
                case ELEMENT_TYPE_SIGNATURE_ATTRIBUTE_ALGORITHM:
                    this.signedAttributesAlgorithm = readOnce(child).getDecodedLong();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (aggregationTime == null) {
            throw new InvalidSignatureRFC3161RecordException("RFC3161 record aggregation time is null");
        }
        if (inputHash == null) {
            throw new InvalidSignatureRFC3161RecordException("RFC3161 record input hash is null");
        }
        if (tstInfoPrefix == null) {
            throw new InvalidSignatureRFC3161RecordException("RFC3161 record tstInfoPrefix is null");
        }
        if (tstInfoSuffix == null) {
            throw new InvalidSignatureRFC3161RecordException("RFC3161 record tstInfoSuffix is null");
        }
        if (tstInfoAlgorithm == null) {
            throw new InvalidSignatureRFC3161RecordException("RFC3161 record tstInfoAlgorithm is null");
        }
        if (signedAttributesPrefix == null) {
            throw new InvalidSignatureRFC3161RecordException("RFC3161 record signedAttributesPrefix is null");
        }
        if (signedAttributesSuffix == null) {
            throw new InvalidSignatureRFC3161RecordException("RFC3161 record signedAttributesSuffix is null");
        }
        if (signedAttributesAlgorithm == null) {
            throw new InvalidSignatureRFC3161RecordException("RFC3161 record signedAttributesAlgorithm is null");
        }
    }

    public DataHash getInputHash() {
        return inputHash;
    }

    public Date getAggregationTime() {
        return aggregationTime;
    }

    public DataHash getOutputHash(HashAlgorithm hashAlgorithm) throws HashException {
        DataHash hash = getInputHash();

        DataHasher hasher = new DataHasher(HashAlgorithm.getById(tstInfoAlgorithm.intValue()));
        hasher.addData(tstInfoPrefix);
        hasher.addData(hash.getValue());
        hasher.addData(tstInfoSuffix);

        hash = hasher.getHash();

        hasher = new DataHasher(HashAlgorithm.getById(signedAttributesAlgorithm.intValue()));
        hasher.addData(signedAttributesPrefix);
        hasher.addData(hash.getValue());
        hasher.addData(signedAttributesSuffix);
        hash = hasher.getHash();

        hasher = new DataHasher(hashAlgorithm);
        hasher.addData(hash.getImprint());

        return hasher.getHash();
    }

    public List<Long> getChainIndex() {
        return chainIndex;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

}
