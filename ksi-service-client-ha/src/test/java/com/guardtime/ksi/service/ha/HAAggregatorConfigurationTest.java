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

import com.guardtime.ksi.pdu.AggregatorConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Arrays;

import static com.guardtime.ksi.hashing.HashAlgorithm.SHA2_256;
import static com.guardtime.ksi.hashing.HashAlgorithm.SHA3_224;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class HAAggregatorConfigurationTest {

    private AggregatorConfiguration subConf1;
    private AggregatorConfiguration subConf2;
    private AggregatorConfiguration subConf3;

    @BeforeMethod
    public void setUp() {
        subConf1 = mock(AggregatorConfiguration.class);
        when(subConf1.getAggregationAlgorithm()).thenReturn(null);
        when(subConf1.getAggregationPeriod()).thenReturn(1000L);
        when(subConf1.getMaximumLevel()).thenReturn(15L);
        when(subConf1.getMaximumRequests()).thenReturn(12L);
        when(subConf1.getParents()).thenReturn(null);

        subConf2 = mock(AggregatorConfiguration.class);
        when(subConf2.getAggregationAlgorithm()).thenReturn(SHA2_256);
        when(subConf2.getAggregationPeriod()).thenReturn(800L);
        when(subConf2.getMaximumLevel()).thenReturn(17L);
        when(subConf2.getMaximumRequests()).thenReturn(10L);
        when(subConf2.getParents()).thenReturn(Arrays.asList("2", "3", "4", "5"));

        subConf3 = mock(AggregatorConfiguration.class);
        when(subConf3.getAggregationAlgorithm()).thenReturn(SHA3_224);
        when(subConf3.getAggregationPeriod()).thenReturn(1200L);
        when(subConf3.getMaximumLevel()).thenReturn(12L);
        when(subConf3.getMaximumRequests()).thenReturn(19L);
        when(subConf3.getParents()).thenReturn(Arrays.asList("4", "5", "6"));
    }

    @Test
    public void testAllClientsHaveSameConf() {
        AggregatorConfiguration configuration = new HAAggregatorConfiguration(Arrays.asList(subConf1, subConf1, subConf1));
        assertNull(configuration.getAggregationAlgorithm());
        assertEquals(configuration.getAggregationPeriod(), new Long(1000));
        assertEquals(configuration.getMaximumLevel(), new Long(15));
        assertEquals(configuration.getMaximumRequests(), new Long(12));
        assertNull(configuration.getParents());
    }

    @Test
    public void testGetMaxRequests() {
        AggregatorConfiguration configuration = new HAAggregatorConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        assertEquals(configuration.getMaximumRequests(), new Long(10L));
    }

    @Test
    public void testGetAggregationPeriod() {
        AggregatorConfiguration configuration = new HAAggregatorConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        assertEquals(configuration.getAggregationPeriod(), new Long(1200L));
    }

    @Test
    public void testGetMaximumLevel() {
        AggregatorConfiguration configuration = new HAAggregatorConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        assertEquals(configuration.getMaximumLevel(), new Long(12L));
    }

    @Test
    public void testGetParents() {
        AggregatorConfiguration configuration = new HAAggregatorConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        assertEquals(configuration.getParents(), Arrays.asList("2", "3", "4", "5"));
    }

    @Test
    public void testGetAggregationAlgorithm() {
        AggregatorConfiguration configuration = new HAAggregatorConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        assertEquals(configuration.getAggregationAlgorithm(), SHA3_224);
    }
}
