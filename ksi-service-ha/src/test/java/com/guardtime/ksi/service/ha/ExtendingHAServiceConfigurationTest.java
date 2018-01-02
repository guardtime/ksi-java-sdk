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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.Date;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class ExtendingHAServiceConfigurationTest {

    private ExtenderConfiguration c1;
    private ExtenderConfiguration c2;

    @BeforeMethod
    public void setUp() throws Exception {
        c1 = mock(ExtenderConfiguration.class);
        c2 = mock(ExtenderConfiguration.class);

        when(c1.getCalendarFirstTime()).thenReturn(new Date(1494504336000L));
        when(c2.getCalendarFirstTime()).thenReturn(new Date(1494504337000L));

        when(c1.getCalendarLastTime()).thenReturn(new Date(1494504338000L));
        when(c2.getCalendarLastTime()).thenReturn(new Date(1494504339000L));

        when(c1.getParents()).thenReturn(null);
        when(c2.getParents()).thenReturn(Collections.singletonList("test_parent"));

        when(c1.getMaximumRequests()).thenReturn(15000L);
        when(c2.getMaximumRequests()).thenReturn(3L);
    }

    @Test
    public void testConstructWithSaneValues() {
        ExtendingHAServiceConfiguration ec = new ExtendingHAServiceConfiguration(c1);
        assertEquals(ec.getCalendarFirstTime(), c1.getCalendarFirstTime());
        assertEquals(ec.getCalendarLastTime(), c1.getCalendarLastTime());
        assertEquals(ec.getParents(), c1.getParents());
        assertEquals(ec.getMaximumRequests(), c1.getMaximumRequests());
    }

    @Test
    public void testConstructWithInsaneValues() {
        when(c1.getCalendarFirstTime()).thenReturn(new Date(100L));
        when(c1.getCalendarLastTime()).thenReturn(new Date(50L));
        when(c1.getMaximumRequests()).thenReturn(17000L);
        ExtendingHAServiceConfiguration ec = new ExtendingHAServiceConfiguration(c1);
        assertNull(ec.getCalendarFirstTime());
        assertNull(ec.getCalendarLastTime());
        assertNull(ec.getMaximumRequests());
    }

    @Test
    public void testConsolidatedMaximumRequests() {
        assertEquals(c1.getMaximumRequests(), new ExtendingHAServiceConfiguration(c1, c2).getMaximumRequests());
    }

    @Test
    public void testConsolidatedParents() {
        assertEquals(c2.getParents(), new ExtendingHAServiceConfiguration(c1, c2).getParents());
    }

    @Test
    public void testConsolidatedCalendarFirstTime() {
        assertEquals(c1.getCalendarFirstTime(), new ExtendingHAServiceConfiguration(c1, c2).getCalendarFirstTime());
    }

    @Test
    public void testConsolidatedCalendarLastTime() {
        assertEquals(c2.getCalendarLastTime(), new ExtendingHAServiceConfiguration(c1, c2).getCalendarLastTime());
    }

    @Test
    public void testConsolidateWithInsaneValues() {
        when(c1.getCalendarFirstTime()).thenReturn(new Date(100L));
        when(c2.getCalendarLastTime()).thenReturn(new Date(0L));
        when(c1.getMaximumRequests()).thenReturn(17000L);
        ExtendingHAServiceConfiguration ec = new ExtendingHAServiceConfiguration(c1, c2);
        assertNull(ec.getCalendarFirstTime());
        assertEquals(ec.getCalendarLastTime(), c1.getCalendarLastTime());
        assertEquals(ec.getMaximumRequests(), c2.getMaximumRequests());
    }

}
