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

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;

public class TCPClientTest {

    private static final TCPClientSettings TCP_SETTINGS_ANON_1 = createTCPSettings("anon", PduVersion.V2);
    private static final TCPClientSettings TCP_SETTINGS_ANON_2 = createTCPSettings("test", PduVersion.V2);

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp =
            "TCPClient.signingSettings.serviceCredentials and TCPClient.extendingSettings.serviceCredentials must match. " +
                    "Use SigningTCPClient and ExtenderTCPClient if they do not match")
    public void testServiceCredentialsMismatch() {
        new TCPClient(TCP_SETTINGS_ANON_1, TCP_SETTINGS_ANON_2);
    }

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp =
            "Extender connection is not configured.*")
    public void testExtendingIfOnlySigningIsConfigured() throws Exception {
        TCPClient tcpClient = new TCPClient(TCP_SETTINGS_ANON_1);
        tcpClient.extend(new ByteArrayInputStream(new byte[] {0}));
    }

    private static TCPClientSettings createTCPSettings(String userPass, PduVersion pduVersion) {
        return new TCPClientSettings("tcp://0.0.0.0:0", 10, new KSIServiceCredentials(userPass, userPass), pduVersion);
    }
}
