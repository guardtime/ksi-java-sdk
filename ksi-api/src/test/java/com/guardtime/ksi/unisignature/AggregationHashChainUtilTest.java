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

package com.guardtime.ksi.unisignature;

import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.AGGREGATION_HASH_CHAIN_WITH_HEIGHT_3;
import static com.guardtime.ksi.Resources.AGGREGATION_HASH_CHAIN_WITH_LEFT_LINK_AND_HEIGHT_1;
import static com.guardtime.ksi.unisignature.AggregationHashChainUtil.calculateIndex;
import static org.testng.Assert.assertEquals;

public class AggregationHashChainUtilTest {

    private InMemoryKsiSignatureComponentFactory signatureComponentFactory;

    @BeforeMethod
    public void setUp() {
        signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Aggregation chain links can not be null")
    public void testCalculateAggregationHashChainIndex_nullChain_throwsNullPointerException() {
        calculateIndex(null);
    }

    @Test
    public void testCalculateIndexWithChainHeight1_Ok() throws Exception {
        AggregationHashChain chain = signatureComponentFactory.createAggregationHashChain(loadTlv(AGGREGATION_HASH_CHAIN_WITH_LEFT_LINK_AND_HEIGHT_1));
        assertEquals(calculateIndex(chain.getChainLinks()), 3L);
    }

    @Test
    public void testCalculateIndexWithChainHeight3_Ok() throws Exception {
        AggregationHashChain chain = signatureComponentFactory.createAggregationHashChain(loadTlv(AGGREGATION_HASH_CHAIN_WITH_HEIGHT_3));
        assertEquals(calculateIndex(chain.getChainLinks()), 15L);
    }
}