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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_PUBLICATION_TIME_FUTURE;
import static com.guardtime.ksi.Resources.SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_PUBLICATION_TIME_PAST;
import static com.guardtime.ksi.Resources.SIGNATURE_CALENDAR_HASH_CHAIN_NO_INPUT_HASH;
import static com.guardtime.ksi.Resources.SIGNATURE_CALENDAR_HASH_CHAIN_NO_LINK;
import static com.guardtime.ksi.Resources.SIGNATURE_CALENDAR_HASH_CHAIN_NO_PUBLICATION_TIME;
import static com.guardtime.ksi.Resources.SIGNATURE_CALENDAR_HASH_CHAIN_OK;
import static com.guardtime.ksi.Resources.SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_ALGORITHM;

public class CalendarHashChainTest {

    @Test
    public void testDecodeCalendarHashChain_Ok() throws Exception {
        InMemoryCalendarHashChain calendarHashChain = load(SIGNATURE_CALENDAR_HASH_CHAIN_OK);
        Assert.assertNotNull(calendarHashChain.getAggregationTime());
        Assert.assertNotNull(calendarHashChain.getRegistrationTime());
        Assert.assertNotNull(calendarHashChain.getElementType(), String.valueOf(0x0802));
        Assert.assertEquals(calendarHashChain.getAggregationTime().getTime(), 1398153270000L);
    }

    @Test(expectedExceptions = InvalidCalendarHashChainException.class, expectedExceptionsMessageRegExp = "Invalid calendar hash chain. Hash algorithm SHA3-256 is not implemented")
    public void testDecodeCalendarHashChainContainingInvalidHashAlgorithm_ThrowsInvalidCalendarHashChainException() throws Exception {
        load(SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_ALGORITHM);
    }

    @Test(expectedExceptions = InvalidCalendarHashChainException.class, expectedExceptionsMessageRegExp = "Calendar hash chain publication time is missing")
    public void testDecodeCalendarHashChainWithoutPublicationTime_ThrowsInvalidCalendarHashChainException() throws Exception {
        load(SIGNATURE_CALENDAR_HASH_CHAIN_NO_PUBLICATION_TIME, InMemoryAggregationHashChain.ELEMENT_TYPE);
    }

    @Test(expectedExceptions = InvalidCalendarHashChainException.class, expectedExceptionsMessageRegExp = "Calendar hash chain input hash is missing")
    public void testDecodeCalendarHashChainWithoutInputHash_ThrowsInvalidCalendarHashChainException() throws Exception {
        load(SIGNATURE_CALENDAR_HASH_CHAIN_NO_INPUT_HASH, InMemoryAggregationHashChain.ELEMENT_TYPE);
    }

    @Test(expectedExceptions = InvalidCalendarHashChainException.class, expectedExceptionsMessageRegExp = "Calendar hash chain does not contain link elements")
    public void testDecodeCalendarHashChainWithoutLinks_ThrowsInvalidCalendarHashChainException() throws Exception {
        load(SIGNATURE_CALENDAR_HASH_CHAIN_NO_LINK, InMemoryAggregationHashChain.ELEMENT_TYPE);
    }

    @Test(expectedExceptions = InvalidCalendarHashChainException.class, expectedExceptionsMessageRegExp = "Calendar hash chain shape is inconsistent with publication time")
    public void testDecodeCalendarHashChainContainingInvalidRegistrationTime_ThrowsInvalidCalendarHashChainException() throws Exception {
        load(SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_PUBLICATION_TIME_PAST, InMemoryAggregationHashChain.ELEMENT_TYPE);
    }

    @Test
    public void testGetRegistrationTimeFromCalendarHashChain_Ok() throws Exception {
        InMemoryCalendarHashChain calendarHashChain = load(SIGNATURE_CALENDAR_HASH_CHAIN_OK);
        Assert.assertEquals(calendarHashChain.getRegistrationTime().getTime(), 1398153270000L);
    }

    @Test(expectedExceptions = InvalidCalendarHashChainException.class, expectedExceptionsMessageRegExp = "Calendar hash chain shape inconsistent with publication time")
    public void testDecodeCalendarHashChainContainingInvalidRegistrationTimeElement_ThrowsInvalidCalendarHashChainException() throws Exception {
        load(SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_PUBLICATION_TIME_FUTURE, InMemoryAggregationHashChain.ELEMENT_TYPE);
    }

    @Test
    public void testCalculateCalendarHashChainOutputHash_Ok() throws Exception {
        InMemoryCalendarHashChain calendarHashChain = load(SIGNATURE_CALENDAR_HASH_CHAIN_OK);
        Assert.assertEquals(calendarHashChain.getInputHash(), new DataHash(HashAlgorithm.SHA1, new byte[]{-95, 124, -102, -86, 97, -24, 10, 27, -9, 29, 13, -123, 10, -12, -27, -70, -87, -128, 11, -67}));
        Assert.assertEquals(calendarHashChain.getOutputHash(), new DataHash(HashAlgorithm.SHA2_256, new byte[]{-118, 71, 62, 38, 49, -108, 26, -97, 14, 78, -13, -19, -53, 77, -14, -74, 125, -85, -30, -126, -120, 41, -60, -47, -41, -82, 60, -104, -22, -40, 13, 58}));
    }

    @Test
    public void testGetPublicationDataFromCalendarHashChain_Ok() throws Exception {
        InMemoryCalendarHashChain calendarHashChain = load(SIGNATURE_CALENDAR_HASH_CHAIN_OK);
        PublicationData publicationData = calendarHashChain.getPublicationData();
        Assert.assertNotNull(publicationData.getPublicationTime());
        Assert.assertNotNull(publicationData.getPublicationDataHash());
        Assert.assertEquals(publicationData.getPublicationDataHash(), new DataHash(HashAlgorithm.SHA2_256, new byte[]{-118, 71, 62, 38, 49, -108, 26, -97, 14, 78, -13, -19, -53, 77, -14, -74, 125, -85, -30, -126, -120, 41, -60, -47, -41, -82, 60, -104, -22, -40, 13, 58}));
        Assert.assertEquals(publicationData.getPublicationTime().getTime(), 1398154864000L);
    }

    static InMemoryCalendarHashChain load(String file) throws Exception {
        return new InMemoryCalendarHashChain(loadTlv(file));
    }

    static InMemoryCalendarHashChain load(String file, int type) throws Exception {
        return new InMemoryCalendarHashChain(loadTlv(file).getFirstChildElement(InMemoryCalendarHashChain.ELEMENT_TYPE));
    }
}
