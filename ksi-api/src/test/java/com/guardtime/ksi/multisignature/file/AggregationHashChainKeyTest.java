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

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;

public class AggregationHashChainKeyTest {

    private Date aggregationTime = new Date();

    @Test
    public void testGetNextKeysFromKeyContainingMultipleIndexes_Ok() throws Exception {
        AggregationHashChainKey key = new AggregationHashChainKey(aggregationTime, Arrays.asList(new Long[]{1L, 2L, 3L, 4L}));
        LinkedList<AggregationHashChainKey> nextKeys = key.getNextKeys();
        Assert.assertNotNull(nextKeys);
        Assert.assertEquals(nextKeys.size(), 3);
        Assert.assertEquals(nextKeys.get(2), new AggregationHashChainKey(aggregationTime, Arrays.asList(new Long[]{1L})));
        Assert.assertEquals(nextKeys.get(1), new AggregationHashChainKey(aggregationTime, Arrays.asList(new Long[]{1L, 2L})));
        Assert.assertEquals(nextKeys.get(0), new AggregationHashChainKey(aggregationTime, Arrays.asList(new Long[]{1L, 2L, 3L})));
    }

    @Test
    public void testGetNextKeysFromKeyContainingZeroIndex_Ok() throws Exception {
        AggregationHashChainKey key = new AggregationHashChainKey(aggregationTime, Arrays.asList(new Long[]{}));
        LinkedList<AggregationHashChainKey> nextKeys = key.getNextKeys();
        Assert.assertNotNull(nextKeys);
        Assert.assertEquals(nextKeys.size(), 0);
    }

    @Test
    public void testGetNextKeysFromKeyContainingOneIndex_Ok() throws Exception {
        AggregationHashChainKey key = new AggregationHashChainKey(aggregationTime, Arrays.asList(new Long[]{1L}));
        LinkedList<AggregationHashChainKey> nextKeys = key.getNextKeys();
        Assert.assertNotNull(nextKeys);
        Assert.assertEquals(nextKeys.size(), 0);
    }

}