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
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.ChainResult;
import com.guardtime.ksi.util.Util;

import java.nio.charset.CharacterCodingException;
import java.util.List;

import static com.guardtime.ksi.unisignature.inmemory.LeftAggregationChainLink.ELEMENT_TYPE_LEFT_LINK;

/**
 * Abstract class for LeftAggregationChainLink and RightAggregationChainLink implementations. AggregationChainLink
 * structure contains the following information: <ul> <li>May contain level correction value. Default value is 0</li>
 * <li>One and only one of the following three fields</li> <ul> <li>sibling hash - an `imprint' representing a hash
 * value from the sibling node in the tree</li> <li>metadata - a sub-structure that provides the ability to incorporate
 * client identity and other information about the request into the hash chain.</li> <li>metadata hash - metadata of
 * limited length encoded as an imprint. This option is present for backwards compatibility with existing signatures
 * created before the structured `metadata' field was introduced.</li> </ul>
 * <p/>
 * </ul>
 */
abstract class InMemoryAggregationChainLink extends TLVStructure implements AggregationChainLink {

    private static final int ELEMENT_TYPE_LEVEL_CORRECTION = 0x01;
    private static final int ELEMENT_TYPE_SIBLING_HASH = 0x02;
    private static final int ELEMENT_TYPE_LEGACY_ID = 0x03;

    private Long levelCorrection = 0L;
    private DataHash siblingHash;
    private byte[] legacyId;
    private LinkMetadata metadata;

    InMemoryAggregationChainLink(TLVElement element) throws KSIException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_LEVEL_CORRECTION:
                    this.levelCorrection = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_SIBLING_HASH:
                    this.siblingHash = readOnce(child).getDecodedDataHash();
                    continue;
                case ELEMENT_TYPE_LEGACY_ID:
                    this.legacyId = readOnce(child).getContent();
                    continue;
                case LinkMetadata.ELEMENT_TYPE_METADATA:
                    this.metadata = new LinkMetadata(readOnce(child));
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }

        // in valid signatures, level values never exceed 8 bits, so the correction amounts should really be even less
        // do the range check at once to prevent possible overflow attacks in hash chain computation
        if (levelCorrection > 0xff) {
            throw new InvalidAggregationHashChainException("Unsupported level correction amount " + levelCorrection);
        }

        // exactly one of the three "sibling data" items must be present
        if (siblingHash == null && legacyId == null && metadata == null) {
            throw new InvalidAggregationHashChainException("AggregationChainLink sibling data must consist of one of the following: 'sibling hash', 'legacy id' or 'metadata'");
        }

        if (siblingHash != null && legacyId != null) {
            throw new InvalidAggregationHashChainException("Multiple sibling data items in hash step. Sibling hash and legacy id are present");
        }

        if (siblingHash != null && metadata != null) {
            throw new InvalidAggregationHashChainException("Multiple sibling data items in hash step. Sibling hash and metadata are present");
        }
        if (legacyId != null && metadata != null) {
            throw new InvalidAggregationHashChainException("Multiple sibling data items in hash step. Legacy id and metadata are present");
        }

    }


    /**
     * This method is used get link identity.
     *
     * @return if metadata is present then the clientId will be returned. If 'legacyId' is present then identity will
     * be decoded from 'legacyId'. Empty string otherwise.
     */
    public String getIdentity() throws InvalidSignatureException {
        if (legacyId != null) {
            return getIdentityFromLegacyId();
        }
        if (metadata != null) {
            return metadata.getClientId();
        }
        return "";
    }

    /**
     * Decodes link identity from legacy id. Throws NullPointerException when legacy id isn't present.
     *
     * @return decoded link identity decoded from legacy id.
     */
    private String getIdentityFromLegacyId() throws InvalidSignatureException {
        byte[] data = legacyId;
        int len = Util.toShort(data, 1);
        if(len > 25) {
            throw new InvalidSignatureException("Decoding link identity from legacy id failed. Invalid legacy id length");
        }
        try {
            return Util.decodeString(data, 3, len);
        } catch (CharacterCodingException e) {
            throw new InvalidSignatureException("Decoding link identity from legacy id failed", e);
        }
    }

    /**
     * Calculates the aggregation chain step result based on last strep imprint, length value and hash algorithm. The
     * specific algorithm depends on which type of {@link AggregationChainLink} implementation is used.
     *
     * @param lastStepImprint
     *         imprint computed in the last step of the previous hash chain component
     * @param length
     *         length computed at the previous step
     * @param algorithm
     *         hash algorithm to be used.
     * @return pair of calculated hash and length.
     */
    public abstract ChainResult calculateChainStep(byte[] lastStepImprint, long length, HashAlgorithm algorithm) throws KSIException;

    /**
     * Hash two hashes together.
     *
     * @param hash1
     *         first hash
     * @param hash2
     *         second hash
     * @param level
     *         level
     * @param hashAlgorithm
     *         hash algorithm to use
     * @return instance of {@link DataHash}
     */
    protected final DataHash hash(byte[] hash1, byte[] hash2, long level, HashAlgorithm hashAlgorithm) throws HashException {
        DataHasher hasher = new DataHasher(hashAlgorithm);
        hasher.addData(hash1);
        hasher.addData(hash2);
        hasher.addData(Util.encodeUnsignedLong(level));
        return hasher.getHash();
    }

    /**
     * @return returns sibling data.
     */
    public byte[] getSiblingData() throws KSIException {
        if (siblingHash != null) {
            return siblingHash.getImprint();
        }

        if (legacyId != null) {
            return legacyId;
        }

        if (metadata != null) {
            return metadata.getRootElement().getContent();
        }
        throw new InvalidAggregationHashChainException("Sibling data not found");
    }

    /**
     * @return will return link level correction or 0 if level correction isn't present.
     */
    public final Long getLevelCorrection() {
        return levelCorrection;
    }

    public byte[] getLegacyId() {
        return legacyId;
    }

    public boolean isLeft() {
        return getElementType() == ELEMENT_TYPE_LEFT_LINK;
    }

    private static class LinkMetadata extends TLVStructure {

        public static final int ELEMENT_TYPE_METADATA = 0x04;

        public static final int ELEMENT_TYPE_CLIENT_ID = 0x01;
        public static final int ELEMENT_TYPE_MACHINE_ID = 0x02;
        public static final int ELEMENT_TYPE_SEQUENCE_NUMBER = 0x03;
        public static final int ELEMENT_TYPE_REQUEST_TIME = 0x04;

        private String clientId;

        public LinkMetadata(TLVElement tlvElement) throws KSIException {
            super(tlvElement);
            List<TLVElement> children = tlvElement.getChildElements();
            for (TLVElement child : children) {
                switch (child.getType()) {
                    case ELEMENT_TYPE_CLIENT_ID:
                        this.clientId = readOnce(child).getDecodedString();
                        continue;
                    case ELEMENT_TYPE_MACHINE_ID:
                    case ELEMENT_TYPE_SEQUENCE_NUMBER:
                    case ELEMENT_TYPE_REQUEST_TIME:
                        readOnce(child);
                        continue;
                    default:
                        verifyCriticalFlag(child);
                }
            }
            if (clientId == null) {
                throw new InvalidAggregationHashChainException("AggregationChainLink metadata does not contain clientId element");
            }

        }

        public String getClientId() {
            return clientId;
        }

        @Override
        public int getElementType() {
            return ELEMENT_TYPE_METADATA;
        }
    }
}
