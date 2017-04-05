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

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.inmemory.PublicationsFilePublicationRecord;
import com.guardtime.ksi.unisignature.CalendarHashChain;
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

public class InMemoryKsiSignatureTest {

    @Test
    public void testParseKSISignature_Ok() throws Exception {
        InMemoryKsiSignature signature = load(TestUtil.load("signature/signature-ok.tlv"));
        Assert.assertNotNull(signature);
    }

    @Test
    public void testSignatureContainsIdentity_Ok() throws Exception {
        KSISignature signature = load(TestUtil.load("signature/signature-with-mixed-aggregation-chains.ksig"));
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
        InMemoryKsiSignature signature = load(TestUtil.load("signature/signature-ok.tlv"));
        Assert.assertEquals(signature.getInputHash(), new DataHash(HashAlgorithm.SHA1, Base16.decode("E9A01D04EBE58F51E4291ADEE6768CE754D155D5")));
        Assert.assertFalse(signature.isPublished());
        Assert.assertEquals(signature.getPublicationTime(), new Date(1396656000000L));
        Assert.assertEquals(signature.getAggregationTime(), new Date(1396608816000L));
    }

    @Test
    public void testLoadSignatureFromFileAndSerialize() throws Exception {
        InputStream input = TestUtil.load("signature/signature-ok.tlv");
        byte[] bytes = Util.toByteArray(input);
        input.close();

        InMemoryKsiSignature signature = load(new ByteArrayInputStream(bytes));
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        signature.writeTo(outBytes);
        Assert.assertEquals(bytes, outBytes.toByteArray());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Output stream can not be null")
    public void testWriteUniSignatureToNullStream_ThrowsKSIException() throws Exception {
        KSISignature signature = load(TestUtil.load("signature/signature-ok.tlv"));
        signature.writeTo(null);
    }

    @Test
    public void testGetInputHashWhenRfc3161RecordIsMissing() throws Exception {
        KSISignature signature = TestUtil.loadSignature("signature/signature-ok.tlv");
        Assert.assertEquals(signature.getInputHash(), signature.getAggregationHashChains()[0].getInputHash());
    }

    @Test
    public void testGetInputHashWhenRfc3161RecordIsPresent() throws Exception {
        KSISignature signature = TestUtil.loadSignature("signature/signature-with-rfc3161-record-ok.ksig");
        Assert.assertNotEquals(signature.getInputHash(), signature.getAggregationHashChains()[0].getInputHash());
        Assert.assertEquals(signature.getInputHash(), signature.getRfc3161Record().getInputHash());
    }

    @Test
    public void testSignatureExtend() throws Exception {
        InMemoryKsiSignature signature = load(TestUtil.load("signature/signature-ok.tlv"));
        Assert.assertFalse(signature.isExtended());
        Assert.assertFalse(signature.isPublished());
        Assert.assertEquals(signature.getPublicationTime(), new Date(1396656000000L));
        Assert.assertEquals(signature.getAggregationTime(), new Date(1396608816000L));

        CalendarHashChain calendarHashChain = CalendarHashChainTest.load("signature/signature-calendar-hash-chain-ok.tlv");
        PublicationsFilePublicationRecord record = new PublicationsFilePublicationRecord(new PublicationData("AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA"));

        KSISignature extendedSignature = signature.extend(calendarHashChain, record);
        Assert.assertTrue(extendedSignature.isExtended());
        Assert.assertFalse(signature.isExtended());
        Assert.assertEquals(extendedSignature.getPublicationTime(), new Date(1398154864000L));
        /*
         * Aggregation time cannot change
         */
        Assert.assertEquals(extendedSignature.getAggregationTime(), new Date(1396608816000L));
        Assert.assertNull(extendedSignature.getCalendarAuthenticationRecord());
        Assert.assertEquals(extendedSignature.getInputHash(), signature.getInputHash());
        Assert.assertEquals(extendedSignature.getCalendarHashChain().getAggregationTime(), new Date(1396608816000L));
    }

    @Test(expectedExceptions = {InvalidAggregationHashChainException.class}, expectedExceptionsMessageRegExp = "Aggregation chain index list can not be empty")
    public void verifyWithEmptyChainIndex_ThrowsException() throws Exception {
        TestUtil.loadSignature("signature-test-pack/invalid-signatures/aggregation-chain/invalid-signature-aggr-chain-chain-index-missing-tag.tlv");
    }

    @Test
    public void testParseSignatureWithMixedAggregationChains_Ok() throws Exception {
        KSISignature signature = TestUtil.loadSignature("signature/signature-with-mixed-aggregation-chains.ksig");
        Assert.assertNotNull(signature);
    }

    @Test(expectedExceptions = InvalidSignatureException.class, expectedExceptionsMessageRegExp = "Found calendar authentication record and publication record. Given elements can not coexist")
    public void testParseSignatureWithPublicationRecordAndCalendarAuthenticationRecord_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature("signature/signature-with-signature-authentication-and-publication-record.ksig");
    }

    @Test(expectedExceptions = InvalidSignatureException.class, expectedExceptionsMessageRegExp = "Found calendar authentication record without calendar hash chain")
    public void testParseSignatureWithPublicationRecordAndWithoutCalendarHashChain_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature("signature/signature-with-publication-record-and-without-calendar-hash-chain.ksig");
    }

    @Test(expectedExceptions = InvalidSignatureException.class, expectedExceptionsMessageRegExp = "Found calendar authentication record without calendar hash chain")
    public void testParseSignatureWithCalendarAuthenticationRecordAndWithoutCalendarHashChain_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature("signature/signature-with-calendar-auth-record-and-without-calendar-hash-chain.ksig");
    }

    @Test(expectedExceptions = InvalidSignatureException.class, expectedExceptionsMessageRegExp = "At least one aggregation chain required")
    public void testParseSignatureWithoutAggregationHashChains_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature("signature/signature-without-aggregation-hash-chains.ksig");
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Invalid legacyId length")
    public void testParseSignatureWithInvalidLegacyIdLength() throws Exception {
        TestUtil.loadSignature("signature/legacy-id/too-long-legacy-id.ksig");
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Invalid legacyId prefix")
    public void testParseSignatureWithInvalidLegacyIdPrefix() throws Exception {
        TestUtil.loadSignature("signature/legacy-id/invalid-legacy-id-prefix.ksig");
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Invalid legacyId embedded data length")
    public void testParseSignatureWithInvalidLegacyIdOctetStringLength() throws Exception {
        TestUtil.loadSignature("signature/legacy-id/invalid-legacy-id-octet-string-padding-length.ksig");
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Invalid legacyId padding")
    public void testParseSignatureWithInvalidLegacyIdOctetStringPadding() throws Exception {
        TestUtil.loadSignature("signature/legacy-id/invalid-legacy-id-ending-byte.ksig");
    }

    private InMemoryKsiSignature load(InputStream file) throws Exception {
        return new InMemoryKsiSignature(loadTlv(file));
    }

}
