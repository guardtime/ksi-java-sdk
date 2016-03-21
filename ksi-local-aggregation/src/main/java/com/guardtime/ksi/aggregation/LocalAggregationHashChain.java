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

package com.guardtime.ksi.aggregation;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.ChainResult;
import com.guardtime.ksi.unisignature.inmemory.InMemoryAggregationChainLink;
import com.guardtime.ksi.unisignature.inmemory.LeftAggregationChainLink;

class LocalAggregationHashChain extends TLVStructure {

    private static final int ELEMENT_TYPE_AGGREGATION_TIME = 0x02;
    private static final int ELEMENT_TYPE_CHAIN_INDEX = 0x03;
    private static final int ELEMENT_TYPE_INPUT_HASH = 0x05;
    private static final int ELEMENT_TYPE_AGGREGATION_ALGORITHM = 0x06;

    protected LinkedList<AggregationChainLink> chain = new LinkedList<AggregationChainLink>();
    private ChainResult latestChainResult;
    private Date aggregationTime;
    private List<Long> chainIndex = new LinkedList<Long>();
    private DataHash inputHash;
    private HashAlgorithm aggregationAlgorithm;
    private DataHash outputHash;

    public LocalAggregationHashChain(DataHash inputHash, SignatureMetadata metadata) throws KSIException {
        this(inputHash, 0L, metadata);
        this.latestChainResult = calculateOutputHash(0L);
    }

    public LocalAggregationHashChain(DataHash inputHash, long level, SignatureMetadata metadata) throws KSIException {
        this.rootElement = new TLVElement(false, false, getElementType());
        this.inputHash = inputHash;

        //input hash
        TLVElement inputHashElement = new TLVElement(false, false, ELEMENT_TYPE_INPUT_HASH);
        inputHashElement.setDataHashContent(inputHash);
        this.rootElement.addChildElement(inputHashElement);

        // hash algorithm
        TLVElement aggregationAlgorithmElement = new TLVElement(false, false, ELEMENT_TYPE_AGGREGATION_ALGORITHM);
        aggregationAlgorithmElement.setLongContent(inputHash.getAlgorithm().getId());
        this.rootElement.addChildElement(aggregationAlgorithmElement);
        this.aggregationAlgorithm = inputHash.getAlgorithm();

        //links
        LeftAggregationChainLink chainLink = new LeftAggregationChainLink(level, metadata.getClientId());
        this.rootElement.addChildElement(chainLink.getRootElement());
        chain.add(chainLink);
        this.latestChainResult = calculateOutputHash(0L);
    }

    public void setAggregationTime(Date aggregationTime) throws TLVParserException {
        TLVElement aggregationTimeElement = new TLVElement(false, false, ELEMENT_TYPE_AGGREGATION_TIME);
        aggregationTimeElement.setLongContent(aggregationTime.getTime() / 1000);
        this.rootElement.addChildElement(aggregationTimeElement);
    }

    public void addChainIndexes(LinkedList<Long> indexes) throws TLVParserException {
        for (Long index : indexes) {
            TLVElement indexElement = new TLVElement(false, false, ELEMENT_TYPE_CHAIN_INDEX);
            indexElement.setLongContent(index);
            this.rootElement.addChildElement(indexElement);
        }
    }

    public void addChainLink(InMemoryAggregationChainLink chainLink) throws KSIException {
        this.chain.add(chainLink);
        this.rootElement.addChildElement(chainLink.getRootElement());
        this.latestChainResult = calculateOutputHash(0L);
    }

    public ChainResult calculateOutputHash(long level) throws KSIException {
        DataHash lastHash = inputHash;
        long currentLevel = level;
        for (AggregationChainLink aggregationChainLink : chain) {
            ChainResult step = aggregationChainLink.calculateChainStep(lastHash.getImprint(), currentLevel, aggregationAlgorithm);
            lastHash = step.getOutputHash();
            currentLevel = step.getLevel();
        }
        this.outputHash = lastHash;
        final long finalCurrentLevel = currentLevel;
        return new ChainResult() {

            public long getLevel() {
                return finalCurrentLevel;
            }

            public DataHash getOutputHash() {
                return outputHash;
            }
        };
    }

    public DataHash getLatestOutputHash() {
        return latestChainResult.getOutputHash();
    }

    public Long getCurrentLevel() {
        return latestChainResult.getLevel();
    }

    @Override
    public int getElementType() {
        return AggregationHashChain.ELEMENT_TYPE;
    }
}


