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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.inmemory.PublicationsFilePublicationRecord;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.util.Base16;
import com.guardtime.ksi.util.Util;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Date;

public class InMemoryKsiSignatureTest {

    @Test
    public void testParseKSISignature_Ok() throws Exception {
        TLVInputStream input = new TLVInputStream(TestUtil.load("signature/signature-ok.tlv"));
        InMemoryKsiSignature signature = new InMemoryKsiSignature(input.readElement());
        Assert.assertNotNull(signature);
    }

    @Test
    public void testLoadSignatureFromFile_Ok() throws Exception {
        InMemoryKsiSignature signature = new InMemoryKsiSignature(new TLVInputStream(TestUtil.load("signature/signature-ok.tlv")).readElement());
        Assert.assertEquals(signature.getInputHash(), new DataHash(HashAlgorithm.SHA1, Base16.decode("E9A01D04EBE58F51E4291ADEE6768CE754D155D5")));
        Assert.assertFalse(signature.isPublished());
        Assert.assertEquals(signature.getIdentity(), "");
        Assert.assertEquals(signature.getPublicationTime(), new Date(1396656000000L));
        Assert.assertEquals(signature.getAggregationTime(), new Date(1396608816000L));
    }

    @Test
    public void testLoadSignatureFromFileAndSerialize() throws Exception {
        InputStream input = TestUtil.load("signature/signature-ok.tlv");
        byte[] bytes = Util.toByteArray(input);
        InMemoryKsiSignature signature = new InMemoryKsiSignature(new TLVInputStream(new ByteArrayInputStream(bytes)).readElement());

        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        signature.writeTo(outBytes);
        Assert.assertEquals(bytes, outBytes.toByteArray());
    }

    @Test
    public void testSignatureExtend() throws Exception {
        InMemoryKsiSignature signature = new InMemoryKsiSignature(new TLVInputStream(TestUtil.load("signature/signature-ok.tlv")).readElement());

        Assert.assertFalse(signature.isPublished());
        Assert.assertEquals(signature.getPublicationTime(), new Date(1396656000000L));
        Assert.assertEquals(signature.getAggregationTime(), new Date(1396608816000L));

        TLVInputStream inputStream = new TLVInputStream(TestUtil.load("signature/signature-calendar-hash-chain-ok.tlv"));
        CalendarHashChain calendarHashChain = new InMemoryCalendarHashChain(inputStream.readElement());
        inputStream.close();
        PublicationsFilePublicationRecord record = new PublicationsFilePublicationRecord(new PublicationData("AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA"));

        InMemoryKsiSignature extendedSignature = signature.extend(calendarHashChain, record);
        Assert.assertTrue(extendedSignature.isPublished());
        Assert.assertEquals(extendedSignature.getPublicationTime(), new Date(1398154864000L));
        /*
         * Aggregation time cannot change
         */
        Assert.assertEquals(extendedSignature.getAggregationTime(), new Date(1396608816000L));
        Assert.assertNull(extendedSignature.getCalendarAuthenticationRecord());
        Assert.assertEquals(extendedSignature.getInputHash(), signature.getInputHash());
        Assert.assertEquals(extendedSignature.getRegistrationTime(), new Date(1396608816000L));
    }

    @Test(expectedExceptions = {InvalidAggregationHashChainException.class}, expectedExceptionsMessageRegExp = "Aggregation chain index list can not be empty")
    public void verifyWithEmptyChainIndex_ThrowsException() throws Exception {
        TestUtil.loadSignature("aggr-chain-chain-index-missing.ksig");
    }

    @Test
    public void testParseSignatureWithMixedAggregationChains_Ok() throws Exception {
        KSISignature signature = TestUtil.loadSignature("signature/signature-with-mixed-aggregation-chains.ksig");
        Assert.assertNotNull(signature);
    }

    @Test(expectedExceptions = InvalidSignatureException.class, expectedExceptionsMessageRegExp = "Aggregation chain indexes are invalid. Invalid length")
    public void testParseSignatureWithMissingAggregationChainIndex_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature("signature/signature-with-missing-one-aggregation-chain.ksig");
    }

    @Test(expectedExceptions = InvalidSignatureException.class, expectedExceptionsMessageRegExp = "Aggregation chain indexes are invalid. Invalid value. Expected .*, got .*")
    public void testParseSignatureWithInvalidAggregationChainIndexValue_ThrowsInvalidSignatureException() throws Exception {
        TestUtil.loadSignature("signature/signature-with-invalid-aggregation-chain-index-value.ksig");
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

}
