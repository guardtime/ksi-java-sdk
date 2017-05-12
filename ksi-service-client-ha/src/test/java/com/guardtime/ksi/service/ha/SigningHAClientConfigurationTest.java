/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.Date;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class SigningHAClientConfigurationTest {

    private AggregatorConfiguration c1;
    private AggregatorConfiguration c2;

    @BeforeMethod
    public void setUp() throws Exception {
        c1 = mock(AggregatorConfiguration.class);
        c2 = mock(AggregatorConfiguration.class);

        when(c1.getAggregationAlgorithm()).thenReturn(HashAlgorithm.SHA2_256);
        when(c2.getAggregationAlgorithm()).thenReturn(null);

        when(c1.getAggregationPeriod()).thenReturn(400L);
        when(c2.getAggregationPeriod()).thenReturn(800L);

        when(c1.getMaximumLevel()).thenReturn(12L);
        when(c2.getMaximumLevel()).thenReturn(10L);

        when(c1.getParents()).thenReturn(null);
        when(c2.getParents()).thenReturn(Collections.singletonList("test_parent"));

        when(c1.getMaximumRequests()).thenReturn(15000L);
        when(c2.getMaximumRequests()).thenReturn(3L);
    }

    @Test
    public void testConstructWithSaneValues() {
        SigningHAClientConfiguration conf = new SigningHAClientConfiguration(c1);
        assertEquals(conf.getAggregationAlgorithm(), c1.getAggregationAlgorithm());
        assertEquals(conf.getAggregationPeriod(), c1.getAggregationPeriod());
        assertEquals(conf.getMaximumLevel(), c1.getMaximumLevel());
        assertEquals(conf.getParents(), c1.getParents());
        assertEquals(conf.getMaximumRequests(), c1.getMaximumRequests());
    }

    @Test
    public void testConstructWithInsaneValues() {
        when(c1.getAggregationPeriod()).thenReturn(20001L);
        when(c1.getMaximumLevel()).thenReturn(21L);
        when(c1.getMaximumRequests()).thenReturn(16001L);
        SigningHAClientConfiguration conf = new SigningHAClientConfiguration(c1);
        assertNull(conf.getAggregationPeriod());
        assertNull(conf.getMaximumLevel());
        assertNull(conf.getMaximumRequests());
    }

    @Test
    public void testConsolidatedMaximumLevel() throws Exception {
        assertEquals(new SigningHAClientConfiguration(c1, c2).getMaximumLevel(), c1.getMaximumLevel());
    }

    @Test
    public void testConsolidatedAggregationAlgorithm() throws Exception {
        assertEquals(new SigningHAClientConfiguration(c1, c2).getAggregationAlgorithm(), c1.getAggregationAlgorithm());
    }

    @Test
    public void testConsolidatedAggregationPeriod() throws Exception {
        assertEquals(new SigningHAClientConfiguration(c1, c2).getAggregationPeriod(), c1.getAggregationPeriod());
    }

    @Test
    public void testConsolidatedMaximumRequests() throws Exception {
        assertEquals(new SigningHAClientConfiguration(c1, c2).getMaximumRequests(), c1.getMaximumRequests());
    }

    @Test
    public void testConsolidatedParents() throws Exception {
        assertEquals(new SigningHAClientConfiguration(c1, c2).getParents(), c2.getParents());
    }

    @Test
    public void testConsolidateWithInsaneValues() throws Exception {
        when(c1.getMaximumLevel()).thenReturn(21L);
        when(c1.getAggregationPeriod()).thenReturn(0L);
        when(c1.getMaximumRequests()).thenReturn(0L);
        SigningHAClientConfiguration conf = new SigningHAClientConfiguration(c1, c2);
        assertEquals(conf.getMaximumLevel(), c2.getMaximumLevel());
        assertEquals(conf.getAggregationPeriod(), c2.getAggregationPeriod());
        assertEquals(conf.getMaximumRequests(), c2.getMaximumRequests());
    }

}
