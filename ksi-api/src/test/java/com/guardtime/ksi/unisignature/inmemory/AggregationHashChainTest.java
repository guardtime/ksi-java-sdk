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

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.unisignature.ChainResult;
import com.guardtime.ksi.util.Base16;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.TestUtil.load;

public class AggregationHashChainTest {

    @Test
    public void testDecodeAggregationHashChain_Ok() throws Exception {
        TLVInputStream inputStream = new TLVInputStream(load("aggregation/aggregation-hash-chain-ok.tlv"));
        InMemoryAggregationHashChain chain = new InMemoryAggregationHashChain(inputStream.readElement());
        inputStream.close();
        Assert.assertEquals(chain.getElementType(), 0x0801);
        Assert.assertNotNull(chain.getAggregationTime());
        Assert.assertEquals(chain.getAggregationTime().getTime(), 1395317319000L);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Aggregation time can not be null")
    public void testDecodeAggregationHashChainWithoutAggregationTime_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVInputStream input = new TLVInputStream(TestUtil.load("aggregation-hash-chain/aggregation-chain-aggregation-time-missing.tlv"));
        try {
            new InMemoryAggregationHashChain(input.readElement());
        } finally {
            input.close();
        }
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Aggregation chain index list can not be empty")
    public void testDecodeAggregationHashChainWithoutChainIndex_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVInputStream input = new TLVInputStream(TestUtil.load("aggregation-hash-chain/aggregation-chain-no-indexes.tlv"));
        try {
            new InMemoryAggregationHashChain(input.readElement());
        } finally {
            input.close();
        }
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Aggregation chain input hash can not be empty")
    public void testDecodeAggregationHashChainWithoutInputHash_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVInputStream input = new TLVInputStream(TestUtil.load("aggregation-hash-chain/aggregation-chain-input-hash-missing.tlv"));
        try {
            new InMemoryAggregationHashChain(input.readElement());
        } finally {
            input.close();
        }
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Aggregation chain aggregation algorithm id can no be null")
    public void testDecodeAggregationHashChainWithoutAggregationAlgorithm_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVInputStream input = new TLVInputStream(TestUtil.load("aggregation-hash-chain/aggregation-chain-algorithm-missing.tlv"));
        try {
            new InMemoryAggregationHashChain(input.readElement());
        } finally {
            input.close();
        }
    }

    @Test
    public void testCalculateAggregationChainHash_Ok() throws Exception {
        TLVInputStream inputStream = new TLVInputStream(load("aggregation/aggregation-hash-chain-ok.tlv"));
        InMemoryAggregationHashChain chain = new InMemoryAggregationHashChain(inputStream.readElement());
        inputStream.close();
        ChainResult chainHash = chain.calculateOutputHash(0L);
        Assert.assertNotNull(chainHash);
        Assert.assertEquals(chainHash.getLevel(), 116L);
        Assert.assertEquals(chainHash.getOutputHash().getImprint(), Base16.decode("01C3EE66A55C8E277D4652549AE076EB22596AB9F56BB0775C62E2E02837A7FDFF"));
    }

    @Test
    public void testGetChainIdentityFromAggregationHashChain_Ok() throws Exception {
        TLVInputStream inputStream = new TLVInputStream(load("aggregation/aggregation-hash-chain-ok.tlv"));
        InMemoryAggregationHashChain chain = new InMemoryAggregationHashChain(inputStream.readElement());
        inputStream.close();
        Assert.assertEquals(chain.getChainIdentity(), "A.B.testA.GT");
    }

}