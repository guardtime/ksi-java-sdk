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

package com.guardtime.ksi.multisignature.file;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.inmemory.PublicationsFilePublicationRecord;
import com.guardtime.ksi.service.ExtensionRequestFuture;
import com.guardtime.ksi.service.KSIService;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVHeader;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.util.Base16;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Date;

public class FileBasedMultiSignatureTest {

    private FileBasedMultiSignatureFactory.FileBasedMultiSignatureWriter signatureWriter;
    private KSIService mockedKsiService;
    private ExtensionRequestFuture mockedExtensionRequestFuture;
    private KSISignatureFactory uniSignatureFactory;

    @BeforeMethod
    public void setUp() throws Exception {
        this.signatureWriter = Mockito.mock(FileBasedMultiSignatureFactory.FileBasedMultiSignatureWriter.class);
        Mockito.doCallRealMethod().when(signatureWriter).write(Mockito.any(FileBasedMultiSignature.class));
        Mockito.doCallRealMethod().when(signatureWriter).write(Mockito.any(Collection.class), Mockito.any(OutputStream.class));
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        mockedKsiService = Mockito.mock(KSIService.class);
        mockedExtensionRequestFuture = Mockito.mock(ExtensionRequestFuture.class);
        Mockito.when(mockedKsiService.extend(Mockito.any(Date.class), Mockito.any(Date.class))).thenReturn(mockedExtensionRequestFuture);
        this.uniSignatureFactory = new InMemoryKsiSignatureFactory();
    }

    @Test(expectedExceptions = InvalidFileBasedMultiSignatureException.class, expectedExceptionsMessageRegExp = "Invalid publications file magic bytes")
    public void testReadMultiSignatureWithoutCorrectHeader_ThrowsInvalidInMemoryMultiSignatureException() throws Exception {
        new FileBasedMultiSignature(TestUtil.load("publications.tlv"), signatureWriter, mockedKsiService, uniSignatureFactory);
    }

    @Test
    public void testReadMultiSignatureWithCorrectHeader_Ok() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        Assert.assertNotNull(multiSignature);
        Assert.assertNotNull(multiSignature.getUsedHashAlgorithms());
        Assert.assertEquals(multiSignature.getUsedHashAlgorithms().length, 0);
    }

    @Test
    public void testAddUniSignaturesFromSameAggregationRoundToContainer_Ok() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_2_agg_time_1437657023.ksig"));
        Assert.assertEquals(multiSignature.getAggregationHashChains().size(), 5);
        Assert.assertEquals(multiSignature.getFirstAggregationHashChains().size(), 3);
        Assert.assertEquals(multiSignature.getUsedHashAlgorithms().length, 1);
        Assert.assertEquals(multiSignature.getCalendarHashChains().size(), 1);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), 1);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), 0);
        Assert.assertEquals(multiSignature.getRfc3161Records().size(), 0);
    }

    @Test
    public void testAddUnextendedAndExtendedSignaturesWithSameDataHash_UnextendedCalendarAuthRecordShouldBeRemoved() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2.ksig"));
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig"));
        KSISignature uniSignature = multiSignature.get(TestUtil.loadSignature("ok-sig-2014-06-2.ksig").getInputHash());
        Assert.assertNotNull(uniSignature.getPublicationRecord());
    }

    @Test
    public void testAddExtendedAndUnextendedSignaturesWithSameDataHash_UnextendedCalendarHashChainShouldNotBeAdded() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig"));
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig"));
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2.ksig"));
        KSISignature uniSignature = multiSignature.get(TestUtil.loadSignature("ok-sig-2014-06-2.ksig").getInputHash());
        Assert.assertNotNull(uniSignature.getPublicationRecord());
    }

    @Test
    public void testGetUniSignatureFromMultiSignature_Ok() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_2_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_2_agg_time_1437657023.ksig"));
        KSISignature uniSignature = multiSignature.get(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("4BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A")));
        Assert.assertNotNull(uniSignature);
        Assert.assertNotNull(uniSignature.getAggregationHashChains());
        Assert.assertNotNull(uniSignature.getCalendarHashChain());
        Assert.assertNotNull(uniSignature.getCalendarAuthenticationRecord());
        Assert.assertNull(uniSignature.getPublicationRecord());
        Assert.assertNull(uniSignature.getRfc3161Record());
    }

    @Test
    public void testMultiSignatureSaving_Ok() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        FileBasedMultiSignature multiSignature2 = new FileBasedMultiSignature(new ByteArrayInputStream(outputStream.toByteArray()), signatureWriter, mockedKsiService, uniSignatureFactory);
        KSISignature uniSignature = multiSignature2.get(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("4BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A")));
        Assert.assertNotNull(uniSignature);
        Assert.assertNotNull(uniSignature.getAggregationHashChains());
        Assert.assertNotNull(uniSignature.getCalendarHashChain());
        Assert.assertNotNull(uniSignature.getCalendarAuthenticationRecord());
        Assert.assertNull(uniSignature.getPublicationRecord());
        Assert.assertNull(uniSignature.getRfc3161Record());
    }

    @Test
    public void testReadMultiSignatureContainingMultipleUniSignatures_Ok() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_2_agg_time_1437657023.ksig"));

        FileBasedMultiSignature multiSignature2 = new FileBasedMultiSignature(new ByteArrayInputStream(outputStream.toByteArray()), signatureWriter, mockedKsiService, uniSignatureFactory);
        KSISignature uniSignature = multiSignature2.get(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("4BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A")));
        Assert.assertNotNull(uniSignature);
        Assert.assertNotNull(uniSignature.getAggregationHashChains());
        Assert.assertNotNull(uniSignature.getCalendarHashChain());
        Assert.assertNotNull(uniSignature.getCalendarAuthenticationRecord());
        Assert.assertNull(uniSignature.getPublicationRecord());
        Assert.assertNull(uniSignature.getRfc3161Record());
    }

    @Test
    public void testReadMultiSignatureContainingUniSignaturesWithRfc3161Record_Ok() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        multiSignature.add(TestUtil.loadSignature("testdata-extended.txt.2015-01.tlv"));

        FileBasedMultiSignature multiSignature2 = new FileBasedMultiSignature(new ByteArrayInputStream(outputStream.toByteArray()), signatureWriter, mockedKsiService, uniSignatureFactory);
        KSISignature uniSignature = multiSignature2.get(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("5466E3CBA14A843A5E93B78E3D6AB8D3491EDCAC7E06431CE1A7F49828C340C3")));
        Assert.assertNotNull(uniSignature);
        Assert.assertNotNull(uniSignature.getAggregationHashChains());
        Assert.assertNotNull(uniSignature.getCalendarHashChain());
        Assert.assertNull(uniSignature.getCalendarAuthenticationRecord());
        Assert.assertNotNull(uniSignature.getPublicationRecord());
        Assert.assertNotNull(uniSignature.getRfc3161Record());
    }

    @Test
    public void testReadMultiSignatureContainingExtendedSignatures_Ok() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        multiSignature.add(TestUtil.loadSignature("testdata-extended.txt.2015-01.tlv"));
        outputStream = new ByteArrayOutputStream();
        Mockito.when(signatureWriter.getOutputStream()).thenReturn(outputStream);
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-04-30.1-extended.ksig"));

        FileBasedMultiSignature multiSignature2 = new FileBasedMultiSignature(new ByteArrayInputStream(outputStream.toByteArray()), signatureWriter, mockedKsiService, uniSignatureFactory);
        Assert.assertEquals(multiSignature2.getAggregationHashChains().size(), 8);
        Assert.assertEquals(multiSignature2.getCalendarHashChains().size(), 3);
        Assert.assertEquals(multiSignature2.getRfc3161Records().size(), 1);
        Assert.assertEquals(multiSignature2.getCalendarAuthenticationRecords().size(), 1);
        Assert.assertEquals(multiSignature2.getSignaturePublicationRecords().size(), 2);

        KSISignature uniSignature = multiSignature2.get(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("5466E3CBA14A843A5E93B78E3D6AB8D3491EDCAC7E06431CE1A7F49828C340C3")));
        Assert.assertNotNull(uniSignature);
        Assert.assertNotNull(uniSignature.getAggregationHashChains());
        Assert.assertNotNull(uniSignature.getCalendarHashChain());
        Assert.assertNull(uniSignature.getCalendarAuthenticationRecord());
        Assert.assertNotNull(uniSignature.getPublicationRecord());
        Assert.assertNotNull(uniSignature.getRfc3161Record());
    }

    @Test
    public void testRemoveUniSignaturesFromMultiSignatureContainingSignaturesFromSameAggregationRound_Ok() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_2_agg_time_1437657023.ksig"));
        multiSignature.remove(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("4BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A")));

        Assert.assertEquals(multiSignature.getAggregationHashChains().size(), 4);
        Assert.assertEquals(multiSignature.getFirstAggregationHashChains().size(), 2);
        Assert.assertEquals(multiSignature.getUsedHashAlgorithms().length, 1);
        Assert.assertEquals(multiSignature.getCalendarHashChains().size(), 1);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), 1);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), 0);
        Assert.assertEquals(multiSignature.getRfc3161Records().size(), 0);
    }

    @Test
    public void testRemoveJustAddedUniSignatureFromMultiSignatureContainer_OK() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.remove(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("6E340B9CFFB37A989CA544E6BB780A2C78901D3FB33738768511A30617AFA01D")));
        Assert.assertEquals(multiSignature.getAggregationHashChains().size(), 0);
        Assert.assertEquals(multiSignature.getCalendarHashChains().size(), 0);
        Assert.assertEquals(multiSignature.getRfc3161Records().size(), 0);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), 0);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), 0);
    }

    @Test
    public void testRemoveJustAddedUniSignaturesFromMultiSignatureContainer_OK() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        multiSignature.remove(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("6E340B9CFFB37A989CA544E6BB780A2C78901D3FB33738768511A30617AFA01D")));
        multiSignature.remove(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("4BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A")));
        Assert.assertEquals(multiSignature.getAggregationHashChains().size(), 0);
        Assert.assertEquals(multiSignature.getCalendarHashChains().size(), 0);
        Assert.assertEquals(multiSignature.getRfc3161Records().size(), 0);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), 0);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), 0);
    }

    @Test
    public void testRemoveUniSignaturesFromMultiSignatureContainingSignaturesFromDifferentAggregationRound_Ok() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2.ksig"));

        int a = multiSignature.getAggregationHashChains().size();
        int b = multiSignature.getCalendarHashChains().size();
        int c = multiSignature.getRfc3161Records().size();
        int d = multiSignature.getCalendarAuthenticationRecords().size();
        int e = multiSignature.getSignaturePublicationRecords().size();

        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        Assert.assertNotEquals(multiSignature.getAggregationHashChains().size(), a);
        Assert.assertEquals(multiSignature.getCalendarHashChains().size(), b);
        Assert.assertEquals(multiSignature.getRfc3161Records().size(), c);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), d);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), e);

        multiSignature.remove(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("4BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A")));

        Assert.assertEquals(multiSignature.getAggregationHashChains().size(), a);
        Assert.assertEquals(multiSignature.getCalendarHashChains().size(), b);
        Assert.assertEquals(multiSignature.getRfc3161Records().size(), c);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), d);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), e);
    }

    @Test
    public void testRemoveUniSignaturesFromMultiSignatureContainingRfc3161Signatures_Ok() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);

        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2.ksig"));

        int a = multiSignature.getAggregationHashChains().size();
        int b = multiSignature.getCalendarHashChains().size();
        int c = multiSignature.getRfc3161Records().size();
        int d = multiSignature.getCalendarAuthenticationRecords().size();
        int e = multiSignature.getSignaturePublicationRecords().size();

        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("testdata.txt.2015-01.tlv"));
        multiSignature.remove(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("4BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A")));
        multiSignature.remove(TestUtil.loadSignature("testdata.txt.2015-01.tlv").getRfc3161Record().getInputHash());

        Assert.assertEquals(multiSignature.getAggregationHashChains().size(), a);
        Assert.assertEquals(multiSignature.getCalendarHashChains().size(), b);
        Assert.assertEquals(multiSignature.getRfc3161Records().size(), c);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), d);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), e);
    }

    @Test
    public void testRemoveExtendedRfc3161UniSignaturesFromMultiSignatureContainer_Ok() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("testdata-extended.txt.2015-01.tlv"));
        multiSignature.remove(TestUtil.loadSignature("testdata-extended.txt.2015-01.tlv").getRfc3161Record().getInputHash());
        Assert.assertEquals(multiSignature.getAggregationHashChains().size(), 0);
        Assert.assertEquals(multiSignature.getCalendarHashChains().size(), 0);
        Assert.assertEquals(multiSignature.getRfc3161Records().size(), 0);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), 0);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), 0);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Input signature can not be null")
    public void testAddNullUniSignatureToMultiSignature_ThrowsKSIException() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input. Document hash is null")
    public void testGetUniSignatureByNullFromMultiSignature_ThrowsKSIException() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.get(null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Signature not found for hash SHA-256.*")
    public void testGetUniSignatureNotPresentInMultiSignature_ThrowsKSIException() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.get(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input. Data hash is null")
    public void testRemoveUniSignatureByNullFromMultiSignature_ThrowsKSIException() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.remove(null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Signature not found for hash SHA-256.*")
    public void testRemoveUniSignatureNotPresentInMultiSignature_ThrowsKSIException() throws Exception {
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.remove(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
    }

    @Test
    public void testExtendMultiSignatureUsingPublicationsFile_Ok() throws Exception {
        Mockito.when(mockedExtensionRequestFuture.getResult()).thenReturn(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig").getCalendarHashChain());
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2.ksig"));
        multiSignature.extend(TestUtil.loadPublicationsFile("publications.tlv"));
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), 1L);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), 1L);
        Mockito.verify(mockedExtensionRequestFuture, Mockito.times(1)).getResult();
    }

    @Test
    public void testExtendMultiSignatureToPublication_Ok() throws Exception {
        Mockito.when(mockedExtensionRequestFuture.getResult()).thenReturn(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig").getCalendarHashChain());
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2.ksig"));
        PublicationRecord firstPublication = TestUtil.loadPublicationsFile("publications.tlv").getPublicationRecord(new Date(1000L));
        multiSignature.extend(firstPublication);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), 0L);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), 2L);
        Mockito.verify(mockedExtensionRequestFuture, Mockito.times(0)).getResult();
    }

    @Test
    public void testExtendAllMultiSignatureToPublication_Ok() throws Exception {
        Mockito.when(mockedExtensionRequestFuture.getResult()).thenReturn(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig").getCalendarHashChain());
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2.ksig"));
        PublicationRecord latestPublication = TestUtil.loadPublicationsFile("publications.tlv").getPublicationRecord(new Date(1413331100000L));
        multiSignature.extend(latestPublication);
        Assert.assertEquals(multiSignature.getSignaturePublicationRecords().size(), 1L);
        Assert.assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), 1L);
        Mockito.verify(mockedExtensionRequestFuture, Mockito.times(1)).getResult();
    }

    @Test
    public void testExtendUniSignaturesFromSameAggregationRound_Ok() throws Exception {
        Mockito.when(mockedExtensionRequestFuture.getResult()).thenReturn(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig").getCalendarHashChain());
        Date date = new Date(System.currentTimeMillis() / 1000 * 1000);
        TLVElement rootElement = new TLVElement(new TLVHeader(false, false, 0x0703));
        rootElement.addChildElement(new PublicationData(date, new DataHash(HashAlgorithm.SHA2_256, new byte[32])).getRootElement());
        PublicationsFilePublicationRecord pubRecord = new PublicationsFilePublicationRecord(rootElement);
        FileBasedMultiSignature multiSignature = new FileBasedMultiSignature(signatureWriter, mockedKsiService, uniSignatureFactory);
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_0_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_1_agg_time_1437657023.ksig"));
        multiSignature.add(TestUtil.loadSignature("multi-signature/one-aggregation-level/signature_data_2_agg_time_1437657023.ksig"));

        multiSignature.extend(pubRecord);
        Mockito.verify(mockedKsiService, Mockito.times(1)).extend(Mockito.any(Date.class), Mockito.any(Date.class));
        Mockito.verify(mockedExtensionRequestFuture, Mockito.times(3)).getResult();
    }

}