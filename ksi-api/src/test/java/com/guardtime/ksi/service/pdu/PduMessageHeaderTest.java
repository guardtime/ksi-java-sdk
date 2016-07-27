/*
 * Copyright 2013-2016 Guardtime, Inc.
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
package com.guardtime.ksi.service.pdu;

import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;


public class PduMessageHeaderTest {

    public static final String TEST_LOGIN_ID = "anon";
    private static final long INSTANCE_ID = 111111L;
    private static final long MESSAGE_ID = 333331L;

    @Test
    public void testCreateMessageHeader_Ok() throws Exception {
        PduMessageHeader messageHeader = new PduMessageHeader(TEST_LOGIN_ID);
        PduMessageHeader header = load(messageHeader.getRootElement().getEncoded());
        Assert.assertEquals(header.getLoginId(), TEST_LOGIN_ID);
        Assert.assertEquals(header.getLoginId(), messageHeader.getLoginId());
    }

    @Test
    public void testCreateMessageHeaderWithMessageId_Ok() throws Exception {
        PduMessageHeader messageHeader = new PduMessageHeader(TEST_LOGIN_ID, INSTANCE_ID, MESSAGE_ID);
        PduMessageHeader header = load(messageHeader.getRootElement().getEncoded());
        Assert.assertEquals(header.getLoginId(), TEST_LOGIN_ID);
        Assert.assertEquals(header.getLoginId(), messageHeader.getLoginId());
        Assert.assertEquals(header.getInstanceId().longValue(), INSTANCE_ID);
        Assert.assertEquals(header.getMessageId().longValue(), MESSAGE_ID);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. LoginId is null.")
    public void testCreateMessageHeaderUsingInvalidLoginId_ThrowsIllegalArgumentException() throws Exception {
        new PduMessageHeader((String) null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. InstanceId is null.")
    public void testCreateMessageHeaderUsingInvalidInstanceId_ThrowsIllegalArgumentException() throws Exception {
        new PduMessageHeader(TEST_LOGIN_ID, null, 1L);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. MessageId is null.")
    public void testCreateMessageHeaderUsingInvalidMessageId_ThrowsIllegalArgumentException() throws Exception {
        new PduMessageHeader(TEST_LOGIN_ID, 1L, null);
    }

    private PduMessageHeader load(byte[] data) throws Exception {
        return new PduMessageHeader(loadTlv(data));
    }

}
