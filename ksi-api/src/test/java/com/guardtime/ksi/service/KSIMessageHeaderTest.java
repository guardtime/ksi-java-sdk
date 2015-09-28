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
package com.guardtime.ksi.service;

import com.guardtime.ksi.tlv.TLVInputStream;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;


public class KSIMessageHeaderTest {

    @Test
    public void testCreateMessageHeader_Ok() throws Exception {
        KSIMessageHeader messageHeader = new KSIMessageHeader("anon");
        TLVInputStream input = new TLVInputStream(new ByteArrayInputStream(messageHeader.getRootElement().getEncoded()));
        KSIMessageHeader header = new KSIMessageHeader(input.readElement());
        input.close();
        Assert.assertEquals(header.getLoginId(), "anon");
        Assert.assertEquals(header.getLoginId(), messageHeader.getLoginId());
    }

    @Test
    public void testCreateMessageHeaderWithMessageId_Ok() throws Exception {
        KSIMessageHeader messageHeader = new KSIMessageHeader("anon", 111111L, 333331L);
        TLVInputStream input = new TLVInputStream(new ByteArrayInputStream(messageHeader.getRootElement().getEncoded()));
        KSIMessageHeader header = new KSIMessageHeader(input.readElement());
        input.close();
        Assert.assertEquals(header.getLoginId(), "anon");
        Assert.assertEquals(header.getLoginId(), messageHeader.getLoginId());
        Assert.assertEquals(header.getInstanceId().longValue(), 111111L);
        Assert.assertEquals(header.getMessageId().longValue(), 333331L);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. LoginId is null.")
    public void testCreateMessageHeaderUsingInvalidLoginId_Throws() throws Exception {
        new KSIMessageHeader((String) null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. InstanceId is null.")
    public void testCreateMessageHeaderUsingInvalidInstanceId_Throws() throws Exception {
        new KSIMessageHeader("anon", null, 1L);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. MessageId is null.")
    public void testCreateMessageHeaderUsingInvalidMessageId_Throws() throws Exception {
        new KSIMessageHeader("anon", 1L, null);
    }

}
