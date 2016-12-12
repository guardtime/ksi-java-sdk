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

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.Identity;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.ChainResult;

/**
 * Aggregation hash chain structures consist of the following fields: <ul> <li>index fields: an `aggregation time' and a
 * sequence of `chain index' values;</li> <li>an `input hash' and an optional `input data': the input for the
 * computation specified by the hash chain;</li> <li>`aggregation algorithm': the one-byte identifier of the hash
 * function used to compute the output hash values of the link structures</li> <li>a sequence of `left link' and `right
 * link' structures</li> </ul>
 */
class InMemoryAggregationHashChain extends TLVStructure implements AggregationHashChain {

    private static final int ELEMENT_TYPE_AGGREGATION_TIME = 0x02;
    private static final int ELEMENT_TYPE_CHAIN_INDEX = 0x03;
    private static final int ELEMENT_TYPE_INPUT_DATA = 0x04;
    private static final int ELEMENT_TYPE_INPUT_HASH = 0x05;
    private static final int ELEMENT_TYPE_AGGREGATION_ALGORITHM = 0x06;

    protected LinkedList<AggregationChainLink> chain = new LinkedList<AggregationChainLink>();
    private Date aggregationTime;
    private List<Long> chainIndex = new LinkedList<Long>();
    @SuppressWarnings("unused")
    private byte[] inputData;
    private DataHash inputHash;
    private HashAlgorithm aggregationAlgorithm;
    private DataHash outputHash;

    public InMemoryAggregationHashChain(DataHash inputHash, Date aggregationTime, LinkedList<Long> chainIndex, LinkedList<AggregationChainLink> links, HashAlgorithm aggregationAlgorithm) throws KSIException {
        this.inputHash = inputHash;
        this.aggregationAlgorithm = aggregationAlgorithm;
        this.aggregationTime = aggregationTime;
        this.chainIndex = chainIndex;
        this.chain = links;

        this.rootElement = new TLVElement(false, false, getElementType());
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_AGGREGATION_TIME, aggregationTime));
        for (Long index : chainIndex) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_CHAIN_INDEX, index));
        }
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_INPUT_HASH, inputHash));
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_AGGREGATION_ALGORITHM, aggregationAlgorithm.getId()));

        for (AggregationChainLink link : links) {
            this.rootElement.addChildElement(((InMemoryAggregationChainLink) link).getRootElement());
        }
    }

    /**
     * Creates aggregation hash chain form TLV element.
     *
     * @param rootElement
     *         - element to be used to createSignature aggregation hash chain
     */
    public InMemoryAggregationHashChain(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_AGGREGATION_TIME:
                    this.aggregationTime = readOnce(child).getDecodedDate();
                    continue;
                case ELEMENT_TYPE_CHAIN_INDEX:
                    this.chainIndex.add(child.getDecodedLong());
                    continue;
                case ELEMENT_TYPE_INPUT_DATA:
                    this.inputData = readOnce(child).getContent();
                    continue;
                case ELEMENT_TYPE_INPUT_HASH:
                    this.inputHash = readOnce(child).getDecodedDataHash();
                    continue;
                case ELEMENT_TYPE_AGGREGATION_ALGORITHM:
                    this.aggregationAlgorithm = readOnce(child).getDecodedHashAlgorithm();
                    continue;
                case LeftAggregationChainLink.ELEMENT_TYPE_LEFT_LINK:
                    this.chain.add(new LeftAggregationChainLink(child));
                    continue;
                case RightAggregationChainLink.ELEMENT_TYPE_RIGHT_LINK:
                    this.chain.add(new RightAggregationChainLink(child));
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }

        if (this.aggregationTime == null) {
            throw new InvalidAggregationHashChainException("Aggregation time can not be null");
        }
        if (this.chainIndex.isEmpty()) {
            throw new InvalidAggregationHashChainException("Aggregation chain index list can not be empty");
        }
        if (this.inputHash == null) {
            throw new InvalidAggregationHashChainException("Aggregation chain input hash can not be empty");
        }
        if (this.aggregationAlgorithm == null) {
            throw new InvalidAggregationHashChainException("Aggregation chain aggregation algorithm id can no be null");
        }
    }

    /**
     * Calculate hash chain output hash.
     *
     * @param level
     *         hash chain level
     * @return hash chain result
     */
    public final ChainResult calculateOutputHash(long level) throws KSIException {
        // TODO task KSIJAVAAPI-207 If the aggregation hash chain component contains the `input data' field, hash the value part of the field
        // using the hash algorithm specified by the first octet of the `input hash' field and verify that the result of
        // hashing `input data' equals `input hash'; terminate with a consistency error if they do not match.(spec. 4.1.1.2)

        // TODO task KSIJAVAAPI-207 if current aggregation hash chain isn't the first component of the hash chain and the chain
        // contains 'input data' field then terminate with a format error. (spec 4.1.1.2)

        DataHash lastHash = inputHash;
        long currentLevel = level;
        for (AggregationChainLink aggregationChainLink : chain) {
            ChainResult step = aggregationChainLink.calculateChainStep(lastHash.getImprint(), currentLevel, aggregationAlgorithm);
            lastHash = step.getOutputHash();
            currentLevel = step.getLevel();
        }
        this.outputHash = lastHash;
        return new InMemoryChainResult(lastHash, currentLevel);
    }

    public HashAlgorithm getAggregationAlgorithm() {
        return aggregationAlgorithm;
    }

    /**
     * @return returns aggregation chain input hash
     */
    public DataHash getInputHash() {
        return inputHash;
    }

    /**
     * @return returns aggregation chain output hash
     */
    public DataHash getOutputHash() {
        return outputHash;
    }

    public List<AggregationChainLink> getChainLinks() {
        return chain;
    }

    /**
     * Returns the (partial) signer identity from the current hash chain.
     */
    public final String getChainIdentity(String separator) throws KSIException {
        StringBuilder identity = new StringBuilder();

        for (int i = chain.size()-1; i >=0 ; i--) {
            AggregationChainLink aggregationChainLink = chain.get(i);
            String id = aggregationChainLink.getIdentity();
            if (identity.length() > 0 && id.length() > 0) {
                identity.append(separator);
            }
            identity.append(id);
        }
        return identity.toString();
    }

    public Identity[] getLinksIdentity() {
        List<Identity> identities = new LinkedList<Identity>();
        for (int i = chain.size()-1; i >=0 ; i--) {
            AggregationChainLink aggregationChainLink = chain.get(i);
            Identity linkIdentity = aggregationChainLink.getLinkIdentity();
            if (linkIdentity != null) {
                identities.add(linkIdentity);
            }
        }
        return identities.toArray(new Identity[identities.size()]);
    }

    public Date getAggregationTime() {
        return aggregationTime;
    }

    public void setAggregationTime(Date aggregationTime) throws TLVParserException {
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_AGGREGATION_TIME, aggregationTime));
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

    public List<Long> getChainIndex() {
        return chainIndex;
    }
}
