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

import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.SubclientConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class HAExtenderConfigurationTest {
    private SubclientConfiguration<ExtenderConfiguration> subConf1;
    private SubclientConfiguration<ExtenderConfiguration> subConf2;
    private SubclientConfiguration<ExtenderConfiguration> subConf3;

    @BeforeMethod
    public void setUp() {
        ExtenderConfiguration sc1 = mock(ExtenderConfiguration.class);
        when(sc1.getCalendarFirstTime()).thenReturn(null);
        when(sc1.getCalendarLastTime()).thenReturn(null);
        when(sc1.getMaximumRequests()).thenReturn(12L);
        when(sc1.getParents()).thenReturn(null);
        subConf1 = new SubclientConfiguration<ExtenderConfiguration>("sc1", sc1);

        ExtenderConfiguration sc2 = mock(ExtenderConfiguration.class);
        when(sc2.getCalendarFirstTime()).thenReturn(new Date(100));
        when(sc2.getCalendarLastTime()).thenReturn(new Date(200));
        when(sc2.getMaximumRequests()).thenReturn(11L);
        when(sc2.getParents()).thenReturn(Arrays.asList("2", "3", "4", "5"));
        subConf2 = new SubclientConfiguration<ExtenderConfiguration>("sc2", sc2);

        ExtenderConfiguration sc3 = mock(ExtenderConfiguration.class);
        when(sc3.getCalendarFirstTime()).thenReturn(new Date(50));
        when(sc3.getCalendarLastTime()).thenReturn(new Date(300));
        when(sc3.getMaximumRequests()).thenReturn(13L);
        when(sc3.getParents()).thenReturn(Arrays.asList("6", "7", "8"));
        subConf3 = new SubclientConfiguration<ExtenderConfiguration>("sc3", sc3);
    }

    @Test
    public void testAllClientsHaveSameConf() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf1, subConf1));
        assertNull(configuration.getCalendarFirstTime());
        assertNull(configuration.getCalendarLastTime());
        assertEquals(configuration.getMaximumRequests(), new Long(12));
        assertNull(configuration.getParents());
    }

    @Test
    public void testGetMaxRequests() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        assertEquals(configuration.getMaximumRequests(), new Long(11L));
    }

    @Test
    public void testGetCalendarFirstTime() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        assertEquals(configuration.getCalendarFirstTime(), new Date(100));
    }

    @Test
    public void testGetCalendarLastTime() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        assertEquals(configuration.getCalendarLastTime().getTime(), new Date(200).getTime());
    }

    @Test
    public void testGetParents() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        assertEquals(configuration.getParents(), Arrays.asList("2", "3", "4", "5"));
    }

    @Test
    public void testGetSubconfigurations() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf2, subConf3));
        List<SubclientConfiguration<ExtenderConfiguration>> subConfigurations = configuration.getSubConfigurations();
        assertEquals(subConfigurations.size(), 3);
    }

}
