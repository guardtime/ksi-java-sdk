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

import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.util.Collections;

import static org.mockito.Mockito.mock;

public class SigningHAClientTest {

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp = "SigningHAClient.sign\\(inputStream\\) is not supported. Use SignerHAClient.sign\\(ksiRequestContext, dataHash, level\\) instead")
    public void testSigningStream() throws Exception {
        SigningHAClient client = new SigningHAClient(
                Collections.singletonList(mock(KSISigningClient.class))
        );
        client.sign(new ByteArrayInputStream(new byte[] {}));
    }
}
