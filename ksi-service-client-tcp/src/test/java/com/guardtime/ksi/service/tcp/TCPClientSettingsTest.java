package com.guardtime.ksi.service.tcp;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.net.InetSocketAddress;

import static org.testng.Assert.*;

public class TCPClientSettingsTest {

    @Test
    public void testGetEndpointReturnsNewInstanceEveryTimeWhenCreatedWithString() throws Exception {
        String uriString = "tcp://www.guardtime.com:80";
        TCPClientSettings settings = new TCPClientSettings(uriString, 0, 0, null, null);
        assertFalse(settings.getEndpoint() == settings.getEndpoint());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testCreateWithNonURIString_ThrowsIllegalArgumentException() throws Exception {
        String uriString = "notAcceptableUri";
        new TCPClientSettings(uriString, 0, 0, null, null);
    }

    @Test
    public void testGetEndpointReturnsSameInstanceEveryTimeWhenCreatedWithInetSocketAddress() throws Exception {
        TCPClientSettings settings = new TCPClientSettings(Mockito.mock(InetSocketAddress.class), 0, 0, null, null);
        assertTrue(settings.getEndpoint() == settings.getEndpoint());
    }

}