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
import com.guardtime.ksi.pdu.SubclientConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;

import static com.guardtime.ksi.hashing.HashAlgorithm.SHA2_256;
import static com.guardtime.ksi.hashing.HashAlgorithm.SHA3_224;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class HAAggregatorConfigurationTest {

    private SubclientConfiguration<AggregatorConfiguration> subConf1;
    private SubclientConfiguration<AggregatorConfiguration> subConf2;
    private SubclientConfiguration<AggregatorConfiguration> subConf3;

    @BeforeMethod
    public void setUp() {
        AggregatorConfiguration sc1 = mock(AggregatorConfiguration.class);
        when(sc1.getAggregationAlgorithm()).thenReturn(null);
        when(sc1.getAggregationPeriod()).thenReturn(1000L);
        when(sc1.getMaximumLevel()).thenReturn(15L);
        when(sc1.getMaximumRequests()).thenReturn(12L);
        when(sc1.getParents()).thenReturn(null);
        subConf1 = new SubclientConfiguration<AggregatorConfiguration>("sc1", sc1);

        AggregatorConfiguration sc2 = mock(AggregatorConfiguration.class);
        when(sc2.getAggregationAlgorithm()).thenReturn(SHA2_256);
        when(sc2.getAggregationPeriod()).thenReturn(800L);
        when(sc2.getMaximumLevel()).thenReturn(17L);
        when(sc2.getMaximumRequests()).thenReturn(10L);
        when(sc2.getParents()).thenReturn(Arrays.asList("2", "3", "4", "5"));
        subConf2 = new SubclientConfiguration<AggregatorConfiguration>("sc2", sc2);

        AggregatorConfiguration sc3 = mock(AggregatorConfiguration.class);
        when(sc3.getAggregationAlgorithm()).thenReturn(SHA3_224);
        when(sc3.getAggregationPeriod()).thenReturn(1200L);
        when(sc3.getMaximumLevel()).thenReturn(12L);
        when(sc3.getMaximumRequests()).thenReturn(19L);
        when(sc3.getParents()).thenReturn(Arrays.asList("4", "5", "6"));
        subConf3 = new SubclientConfiguration<AggregatorConfiguration>("sc3", sc3);
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

    @Test
    public void testGetSubconfigurations() {
        AggregatorConfiguration configuration = new HAAggregatorConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        List<SubclientConfiguration<AggregatorConfiguration>> subConfigurations = configuration.getSubConfigurations();
        assertEquals(subConfigurations.size(), 3);
    }
}
