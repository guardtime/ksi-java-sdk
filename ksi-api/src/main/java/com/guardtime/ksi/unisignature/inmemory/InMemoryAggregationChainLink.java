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
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.ChainResult;
import com.guardtime.ksi.unisignature.Identity;
import com.guardtime.ksi.unisignature.LinkMetadata;
import com.guardtime.ksi.util.Util;

import java.nio.charset.CharacterCodingException;
import java.util.Arrays;
import java.util.List;

import static com.guardtime.ksi.unisignature.inmemory.LeftAggregationChainLink.ELEMENT_TYPE_LEFT_LINK;
import static com.guardtime.ksi.util.Util.copyOf;

/**
 * Abstract class for LeftAggregationChainLink and RightAggregationChainLink implementations. AggregationChainLink
 * structure contains the following information: <ul> <li>a level correction value</li> <li>One and only one of the
 * following three fields</li> <ul> <li>sibling hash - an `imprint' representing a hash value from the sibling node in
 * the tree</li> <li>metadata - a sub-structure that provides the ability to incorporate client identity and other
 * information about the request into the hash chain.</li> <li>legacy client identifier - a client identifier converted
 * from a legacy signature. This option is present for backwards compatibility with existing signatures created before
 * the structured `metadata' field was introduced.</li> </ul>
 * <p/>
 * </ul>
 */
abstract class InMemoryAggregationChainLink extends TLVStructure implements AggregationChainLink {

    private static final int ELEMENT_TYPE_LEVEL_CORRECTION = 0x01;
    private static final int ELEMENT_TYPE_SIBLING_HASH = 0x02;
    private static final int ELEMENT_TYPE_LEGACY_ID = 0x03;

    private static final int LEGACY_ID_LENGTH = 29;
    private static final byte[] LEGACY_ID_PREFIX = new byte[]{0x03, 0x00};
    private static final int LEGACY_ID_OCTET_STRING_MAX_LENGTH = 25;

    private long levelCorrection = 0L;
    private DataHash siblingHash;
    private byte[] legacyId;
    private InMemoryLinkMetadata metadata;

    InMemoryAggregationChainLink(DataHash siblingHash, long levelCorrection) throws KSIException {
        this.levelCorrection = levelCorrection;
        this.siblingHash = siblingHash;
        this.rootElement = new TLVElement(false, false, getElementType());
        addLevelCorrectionTlvElement();
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_SIBLING_HASH, siblingHash));
    }

    InMemoryAggregationChainLink(LinkMetadata linkMetadata, long levelCorrection) throws KSIException {
        this.levelCorrection = levelCorrection;
        this.rootElement = new TLVElement(false, false, getElementType());
        addLevelCorrectionTlvElement();
        if (linkMetadata instanceof InMemoryLinkMetadata) {
            this.metadata = (InMemoryLinkMetadata) linkMetadata;
        } else {
            this.metadata = new InMemoryLinkMetadata(linkMetadata.getDecodedClientId(), linkMetadata.getDecodedMachineId(), linkMetadata.getSequenceNumber(), linkMetadata.getRequestTime());
        }
        this.rootElement.addChildElement(metadata.getRootElement());

    }

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
                    verifyLegacyId(legacyId);
                    continue;
                case InMemoryLinkMetadata.ELEMENT_TYPE_METADATA:
                    this.metadata = new InMemoryLinkMetadata(readOnce(child));
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

    private void verifyLegacyId(byte[] legacyId) throws InvalidAggregationHashChainException {
        if (legacyId.length != LEGACY_ID_LENGTH) {
            throw new InvalidAggregationHashChainException("Invalid legacyId length");
        }
        if (!Arrays.equals(LEGACY_ID_PREFIX, copyOf(legacyId, 0, 2))) {
            throw new InvalidAggregationHashChainException("Invalid legacyId prefix");
        }
        int length = Util.toShort(legacyId, 1);
        if (length > LEGACY_ID_OCTET_STRING_MAX_LENGTH) {
            throw new InvalidAggregationHashChainException("Invalid legacyId embedded data length");
        }
        int contentLength = length + 3;
        if (!Arrays.equals(new byte[LEGACY_ID_LENGTH - contentLength], copyOf(legacyId, contentLength, legacyId.length - contentLength))) {
            throw new InvalidAggregationHashChainException("Invalid legacyId padding");
        }
    }

    /**
     * This method is used get link identity.
     *
     * @return if metadata is present then the clientId will be returned. If 'legacyId' is present then identity will be
     * decoded from 'legacyId'. Empty string otherwise.
     *  @deprecated use {@link InMemoryAggregationChainLink#getLinkIdentity()} instead
     */
    @Deprecated
    public String getIdentity() throws InvalidSignatureException {
        if (legacyId != null) {
            try {
                return getIdentityFromLegacyId();
            } catch (CharacterCodingException e) {
                throw new InvalidSignatureException("Decoding link identity from legacy id failed", e);
            }
        }
        if (metadata != null) {
            return metadata.getDecodedClientId();
        }
        return "";
    }

    public Identity getLinkIdentity() {
        Identity identity = null;
        if (legacyId != null) {
            try {
                identity = new LegacyIdentity(getIdentityFromLegacyId());
            } catch (CharacterCodingException e) {
                throw new IllegalArgumentException(e);
            }
        } else if (metadata != null) {
            identity = metadata;
        }
        return identity;
    }

    /**
     * Decodes link identity from legacy id.
     *
     * @return decoded link identity decoded from legacy id.
     */
    private String getIdentityFromLegacyId() throws CharacterCodingException {
        byte[] data = legacyId;
        int len = Util.toShort(data, 1);
        return Util.decodeString(data, 3, len);
    }

    /**
     * Calculates the aggregation chain step result based on last strep imprint, length value and hash algorithm. The
     * specific algorithm depends on which type of {@link AggregationChainLink} implementation is used.
     *
     * @param lastStepImprint imprint computed in the last step of the previous hash chain component
     * @param length          length computed at the previous step
     * @param algorithm       hash algorithm to be used.
     * @return pair of calculated hash and length.
     */
    public abstract ChainResult calculateChainStep(byte[] lastStepImprint, long length, HashAlgorithm algorithm) throws KSIException;

    /**
     * Hash two hashes together.
     *
     * @param hash1     first hash
     * @param hash2     second hash
     * @param level     level
     * @param algorithm hash algorithm to use
     * @return instance of {@link DataHash}
     */
    protected final DataHash hash(byte[] hash1, byte[] hash2, long level, HashAlgorithm algorithm) throws InvalidAggregationHashChainException {
        if (!algorithm.isImplemented()) {
            throw new InvalidAggregationHashChainException("Invalid aggregation hash chain. Hash algorithm " + algorithm.getName() + " is not implemented");
        }
        DataHasher hasher = new DataHasher(algorithm, false);
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

    public final Long getLevelCorrection() {
        return levelCorrection;
    }

    private void addLevelCorrectionTlvElement() throws TLVParserException {
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_LEVEL_CORRECTION, this.levelCorrection));
    }

    public boolean isLeft() {
        return getElementType() == ELEMENT_TYPE_LEFT_LINK;
    }

    public LinkMetadata getMetadata() {
        return metadata;
    }

}
