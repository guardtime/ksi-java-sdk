package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.pdu.ExtenderConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Date;

import static java.util.Collections.singletonList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class HAExtenderConfigurationTest {
    private ExtenderConfiguration subConf1;
    private ExtenderConfiguration subConf2;
    private ExtenderConfiguration subConf3;

    @BeforeMethod
    public void setUp() {
        subConf1 = mock(ExtenderConfiguration.class);
        when(subConf1.getCalendarFirstTime()).thenReturn(null);
        when(subConf1.getCalendarLastTime()).thenReturn(null);
        when(subConf1.getMaximumRequests()).thenReturn(12L);
        when(subConf1.getParents()).thenReturn(null);

        subConf2 = mock(ExtenderConfiguration.class);
        when(subConf2.getCalendarFirstTime()).thenReturn(new Date(100));
        when(subConf2.getCalendarLastTime()).thenReturn(new Date(200));
        when(subConf2.getMaximumRequests()).thenReturn(11L);
        when(subConf2.getParents()).thenReturn(Arrays.asList("2", "3", "4", "5"));

        subConf3 = mock(ExtenderConfiguration.class);
        when(subConf3.getCalendarFirstTime()).thenReturn(new Date(50));
        when(subConf3.getCalendarLastTime()).thenReturn(new Date(300));
        when(subConf3.getMaximumRequests()).thenReturn(13L);
        when(subConf3.getParents()).thenReturn(Arrays.asList("6", "7", "8"));
    }

    @Test
    public void testAllClientsHaveSameConf() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf1, subConf1), 3, 3);
        assertNull(configuration.getCalendarFirstTime());
        assertNull(configuration.getCalendarLastTime());
        assertEquals(configuration.getMaximumRequests(), new Long(12));
        assertNull(configuration.getParents());
    }

    @Test
    public void testGetMaxRequestsWhenLoadBalancing() {
        assertEquals(new HAExtenderConfiguration(singletonList(subConf1), 3, 2).getMaximumRequests(), new Long(18));
        assertEquals(new HAExtenderConfiguration(singletonList(subConf1), 3, 1).getMaximumRequests(), new Long(36));
    }

    @Test
    public void testGetMaxRequests() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf2, subConf3), 3, 3);
        assertEquals(configuration.getMaximumRequests(), new Long(11L));
    }

    @Test
    public void testGetCalendarFirstTime() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf2, subConf3), 3, 3);
        assertEquals(configuration.getCalendarFirstTime(), new Date(100));
    }

    @Test
    public void testGetCalendarLastTime() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf2, subConf3), 3, 3);
        assertEquals(configuration.getCalendarLastTime().getTime(), new Date(200).getTime());
    }

    @Test
    public void testGetParents() {
        ExtenderConfiguration configuration = new HAExtenderConfiguration(Arrays.asList(subConf1, subConf2, subConf3), 3, 3);
        assertEquals(configuration.getParents(), Arrays.asList("2", "3", "4", "5"));
    }

}
