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

package com.guardtime.ksi.service.tcp;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.net.InetSocketAddress;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class TCPClientSettingsTest {

    @Test
    public void testGetEndpointReturnsNewInstanceEveryTimeWhenCreatedWithString() throws Exception {
        String uriString = "tcp://www.guardtime.com:80";
        TCPClientSettings settings = new TCPClientSettings(uriString, 0, null, null);
        assertFalse(settings.getEndpoint() == settings.getEndpoint());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testCreateWithNonURIString_ThrowsIllegalArgumentException() throws Exception {
        String uriString = "notAcceptableUri";
        new TCPClientSettings(uriString, 0, null, null);
    }

    @Test
    public void testGetEndpointReturnsSameInstanceEveryTimeWhenCreatedWithInetSocketAddress() throws Exception {
        TCPClientSettings settings = new TCPClientSettings(Mockito.mock(InetSocketAddress.class), 0, null, null);
        assertTrue(settings.getEndpoint() == settings.getEndpoint());
    }

}
