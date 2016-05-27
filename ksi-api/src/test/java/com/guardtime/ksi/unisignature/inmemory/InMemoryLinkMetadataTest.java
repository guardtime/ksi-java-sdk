/*
 * Copyright 2013-2015 Guardtime, Inc.
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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.tlv.TLVElement;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class InMemoryLinkMetadataTest {

    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_MACHINE_ID = "test-machine-id";
    private static final Long CURRENT_TIME = System.currentTimeMillis();
    private static final Long TEST_SEQUENCE_NUMBER = 1L;

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Client Identifier can not be null")
    public void testCreateNewLeftLinkWithoutClientId_ThrowsNullPointerException() throws Exception {
        new InMemoryLinkMetadata((String) null);
    }

    @Test
    public void testCreateNewLeftLink() throws Exception {
        InMemoryLinkMetadata metadata = new InMemoryLinkMetadata(TEST_CLIENT_ID, TEST_MACHINE_ID, TEST_SEQUENCE_NUMBER, CURRENT_TIME);
        assertEquals(metadata.getClientId(), TEST_CLIENT_ID);
        TLVElement rootElement = metadata.getRootElement();
        assertEquals(5, rootElement.getChildElements().size());
        int paddingLength = 2;
        assertEquals(rootElement.getChildElements().get(0).getContentLength(), paddingLength);
        assertEquals(rootElement.getChildElements().get(1).getDecodedString(), TEST_CLIENT_ID);
        assertEquals(rootElement.getChildElements().get(2).getDecodedString(), TEST_MACHINE_ID);
        assertEquals(rootElement.getChildElements().get(3).getDecodedLong(), TEST_SEQUENCE_NUMBER);
        assertEquals(rootElement.getChildElements().get(4).getDecodedLong(), CURRENT_TIME);
    }

    @Test
    public void testCreateNewLeftLinkWithClientId() throws Exception {
        InMemoryLinkMetadata metadata = new InMemoryLinkMetadata(TEST_CLIENT_ID);
        assertEquals(metadata.getClientId(), TEST_CLIENT_ID);
        TLVElement rootElement = metadata.getRootElement();
        assertEquals(2, rootElement.getChildElements().size());
        int paddingLength = 1;
        assertEquals(rootElement.getChildElements().get(0).getContentLength(), paddingLength);
        assertEquals(rootElement.getChildElements().get(1).getDecodedString(), TEST_CLIENT_ID);
    }

}
