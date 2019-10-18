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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.unisignature.Identity;
import com.guardtime.ksi.unisignature.IdentityType;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.util.Base16;
import com.guardtime.ksi.util.Util;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Date;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.RFC3161_MISSING_CHAIN_INDEXES;
import static com.guardtime.ksi.Resources.RFC3161_SIGNATURE;
import static com.guardtime.ksi.Resources.SIGANTURE_AGGREGATION_HASH_CHAIN_NO_AGGREGATION_CHAINS;
import static com.guardtime.ksi.Resources.SIGANTURE_CALENDAR_AUTH_BUT_NO_CALAENDAR;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_CHANGED_CHAIN_ORDER;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_MISSING_CHAIN_INDEX;
import static com.guardtime.ksi.Resources.SIGNATURE_LEGACY_ID_INVALID_ENDING_BYTE;
import static com.guardtime.ksi.Resources.SIGNATURE_LEGACY_ID_INVALID_OCTET_STRING_PADDING_LENGTH;
import static com.guardtime.ksi.Resources.SIGNATURE_LEGACY_ID_INVALID_PREFIX;
import static com.guardtime.ksi.Resources.SIGNATURE_LEGACY_ID_TOO_LONG;
import static com.guardtime.ksi.Resources.SIGNATURE_PUBLICATION_RECORD_BUT_NO_CALENDAR;
import static com.guardtime.ksi.Resources.SIGNATURE_WITH_CAL_AUTH_AND_PUB_REC;

public class InMemoryKsiSignatureTest {

    @Test
    public void testParseKSISignature_Ok() throws Exception {
        InMemoryKsiSignature signature = load(TestUtil.load(SIGNATURE_2017_03_14));
        Assert.assertNotNull(signature);
    }

    @Test
    public void testSignatureContainsIdentity_Ok() throws Exception {
        KSISignature signature = load(TestUtil.load(SIGNATURE_AGGREGATION_HASH_CHAIN_CHANGED_CHAIN_ORDER));
        Assert.assertNotNull(signature.getAggregationHashChainIdentity());
        Identity[] chainIdentity = signature.getAggregationHashChainIdentity();
        Assert.assertNotNull(chainIdentity);
        Assert.assertEquals(chainIdentity[0].getDecodedClientId(), "GT");
        Assert.assertEquals(chainIdentity[0].getType(), IdentityType.LEGACY);
        Assert.assertEquals(chainIdentity[chainIdentity.length-1].getDecodedClientId(), "anon");
        Assert.assertEquals(chainIdentity[chainIdentity.length-1].getType(),IdentityType.METADATA);
    }

    @Test
    public void testLoadSignatureFromFile_Ok() throws Exception {
        InMemoryKsiSignature signature = load(TestUtil.load(SIGNATURE_2017_03_14));
        Assert.assertEquals(signature.getInputHash(), new DataHash(Base16.decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
        Assert.assertFalse(signature.isPublished());
        Assert.assertEquals(signature.getPublicationTime(), new Date(1489520040000L));
        Assert.assertEquals(signature.getAggregationTime(), new Date(1489520040000L));
    }

    @Test
    public void testLoadSignatureFromFileAndSerialize() throws Exception {
        InputStream input = TestUtil.load(SIGNATURE_2017_03_14);
        byte[] bytes = Util.toByteArray(input);
        input.close();

        InMemoryKsiSignature signature = load(new ByteArrayInputStream(bytes));
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        signature.writeTo(outBytes);
        Assert.assertEquals(bytes, outBytes.toByteArray());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Output stream can not be null")
    public void testWriteUniSignatureToNullStream_ThrowsKSIException() throws Exception {
        KSISignature signature = load(TestUtil.load(SIGNATURE_2017_03_14));
        signature.writeTo(null);
    }

    @Test
    public void testGetInputHashWhenRfc3161RecordIsMissing() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2017_03_14);
        Assert.assertEquals(signature.getInputHash(), signature.getAggregationHashChains()[0].getInputHash());
    }

    @Test
    public void testGetInputHashWhenRfc3161RecordIsPresent() throws Exception {
        KSISignature signature = TestUtil.loadSignature(RFC3161_SIGNATURE);
        Assert.assertNotEquals(signature.getInputHash(), signature.getAggregationHashChains()[0].getInputHash());
        Assert.assertEquals(signature.getInputHash(), signature.getRfc3161Record().getInputHash());
    }

    @Test(expectedExceptions = {InvalidAggregationHashChainException.class}, expectedExceptionsMessageRegExp = "Aggregation chain index list can not be empty")
    public void verifyWithEmptyChainIndex_ThrowsException() throws Exception {
        TestUtil.loadSignature(SIGNATURE_AGGREGATION_HASH_CHAIN_MISSING_CHAIN_INDEX);
    }

    @Test
    public void testParseSignatureWithMixedAggregationChains_Ok() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_AGGREGATION_HASH_CHAIN_CHANGED_CHAIN_ORDER);
        Assert.assertNotNull(signature);
    }

    @Test(expectedExceptions = InvalidSignatureException.class,
            expectedExceptionsMessageRegExp = "Found calendar authentication record and publication record. Given elements can not coexist")
    public void testParseSignatureWithPublicationRecordAndCalendarAuthenticationRecord_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature(SIGNATURE_WITH_CAL_AUTH_AND_PUB_REC);
    }

    @Test(expectedExceptions = InvalidSignatureRFC3161RecordException.class, expectedExceptionsMessageRegExp = "RFC3161 record chain index is null")
    public void testParseSignatureWithRfc3161RecordIsMissingChainIndex() throws Exception {
        TestUtil.loadSignature(RFC3161_MISSING_CHAIN_INDEXES);
    }

    @Test(expectedExceptions = InvalidSignatureException.class, expectedExceptionsMessageRegExp = "Found calendar authentication record without calendar hash chain")
    public void testParseSignatureWithPublicationRecordAndWithoutCalendarHashChain_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature(SIGNATURE_PUBLICATION_RECORD_BUT_NO_CALENDAR);
    }

    @Test(expectedExceptions = InvalidSignatureException.class, expectedExceptionsMessageRegExp = "Found calendar authentication record without calendar hash chain")
    public void testParseSignatureWithCalendarAuthenticationRecordAndWithoutCalendarHashChain_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature(SIGANTURE_CALENDAR_AUTH_BUT_NO_CALAENDAR);
    }

    @Test(expectedExceptions = InvalidSignatureException.class, expectedExceptionsMessageRegExp = "At least one aggregation chain required")
    public void testParseSignatureWithoutAggregationHashChains_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature(SIGANTURE_AGGREGATION_HASH_CHAIN_NO_AGGREGATION_CHAINS);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Invalid legacyId length")
    public void testParseSignatureWithInvalidLegacyIdLength() throws Exception {
        TestUtil.loadSignature(SIGNATURE_LEGACY_ID_TOO_LONG);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Invalid legacyId prefix")
    public void testParseSignatureWithInvalidLegacyIdPrefix() throws Exception {
        TestUtil.loadSignature(SIGNATURE_LEGACY_ID_INVALID_PREFIX);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Invalid legacyId embedded data length")
    public void testParseSignatureWithInvalidLegacyIdOctetStringLength() throws Exception {
        TestUtil.loadSignature(SIGNATURE_LEGACY_ID_INVALID_OCTET_STRING_PADDING_LENGTH);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Invalid legacyId padding")
    public void testParseSignatureWithInvalidLegacyIdOctetStringPadding() throws Exception {
        TestUtil.loadSignature(SIGNATURE_LEGACY_ID_INVALID_ENDING_BYTE);
    }

    private InMemoryKsiSignature load(InputStream file) throws Exception {
        return new InMemoryKsiSignature(loadTlv(file));
    }

}
