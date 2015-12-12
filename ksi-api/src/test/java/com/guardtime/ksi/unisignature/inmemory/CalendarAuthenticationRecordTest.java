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

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.tlv.TLVInputStream;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CalendarAuthenticationRecordTest {

    @Test
    public void testDecodeCalendarAuthenticationRecord_Ok() throws Exception {
        InMemoryCalendarAuthenticationRecord record = load("calendar-authentication-record/calendar-authentication-record-ok.tlv");
        Assert.assertNotNull(record.getPublicationData());
        Assert.assertNotNull(record.getSignatureData());
    }

    @Test(expectedExceptions = InvalidCalendarAuthenticationRecordException.class, expectedExceptionsMessageRegExp = "Calendar authentication does not contain publication data")
    public void testDecodeCalendarAuthenticationRecordWithoutPublicationData_ThrowsInvalidCalendarAuthenticationRecordException() throws Exception {
        load("calendar-authentication-record/calendar-authentication-record-without-publication-data.tlv");
    }

    @Test(expectedExceptions = InvalidCalendarAuthenticationRecordException.class, expectedExceptionsMessageRegExp = "Calendar authentication record does not contain signature data")
    public void testDecodeCalendarAuthenticationRecordWithoutSignatureData_ThrowsInvalidCalendarAuthenticationRecordException() throws Exception {
        load("calendar-authentication-record/calendar-authentication-record-without-signature-data.tlv");
    }

    private InMemoryCalendarAuthenticationRecord load(String file) throws Exception {
        TLVInputStream input = new TLVInputStream(TestUtil.load(file));
        try {
            return new InMemoryCalendarAuthenticationRecord(input.readElement());
        } finally {
            input.close();
        }
    }

}