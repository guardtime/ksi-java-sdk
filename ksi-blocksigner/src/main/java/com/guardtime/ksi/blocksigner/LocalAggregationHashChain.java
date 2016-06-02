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

package com.guardtime.ksi.blocksigner;

import java.util.LinkedList;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.ChainResult;
import com.guardtime.ksi.unisignature.IdentityMetadata;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;

class LocalAggregationHashChain {

    private static final InMemoryKsiSignatureFactory SIGNATURE_ELEMENT_FACTORY = new InMemoryKsiSignatureFactory();
    private final HashAlgorithm hashAlgorithm;
    private ChainResult latestChainResult;
    private LinkedList<AggregationChainLink> links = new LinkedList<AggregationChainLink>();

    private DataHash inputHash;
    private DataHash currentOutputHash;
    private long currentLevel;

    public LocalAggregationHashChain(DataHash inputHash, long level, IdentityMetadata metadata, HashAlgorithm hashAlgorithm) throws KSIException {
        this.inputHash = inputHash;
        this.hashAlgorithm = hashAlgorithm;
        this.currentOutputHash = inputHash;
        AggregationChainLink link = SIGNATURE_ELEMENT_FACTORY.createLeftAggregationChainLink(metadata, level);
        links.addLast(link);
        this.latestChainResult = calculateOutputHash(0L);
    }

    public void addChainLink(AggregationChainLink chainLink) throws KSIException {
        this.links.add(chainLink);
        this.latestChainResult = calculateOutputHash(0L);
    }

    public ChainResult calculateOutputHash(long level) throws KSIException {
        DataHash lastHash = inputHash;
        long calculatedLevel = level;
        for (AggregationChainLink aggregationChainLink : links) {
            ChainResult step = aggregationChainLink.calculateChainStep(lastHash.getImprint(), calculatedLevel, hashAlgorithm);
            lastHash = step.getOutputHash();
            calculatedLevel = step.getLevel();
        }
        this.currentOutputHash = lastHash;
        currentLevel = calculatedLevel;
        return new ChainResult() {

            public long getLevel() {
                return currentLevel;
            }

            public DataHash getOutputHash() {
                return currentOutputHash;
            }
        };
    }

    public DataHash getLatestOutputHash() {
        return latestChainResult.getOutputHash();
    }

    public Long getCurrentLevel() {
        return latestChainResult.getLevel();
    }

    public DataHash getInputHash() {
        return inputHash;
    }

    public LinkedList<AggregationChainLink> getLinks() {
        return links;
    }
}


