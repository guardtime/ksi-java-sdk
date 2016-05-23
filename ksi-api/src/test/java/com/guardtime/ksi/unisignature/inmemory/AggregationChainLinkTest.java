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

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.SignatureMetadata;
import com.guardtime.ksi.util.Base16;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.Date;

public class AggregationChainLinkTest {

    private static final byte[] LEGACY_ID_CONTENT = Base16.decode("03:00034142430000000000000000000000000000000000000000000000");
    private TLVElement siblingHash;
    private TLVElement legacyId;
    private TLVElement metadata;

    @BeforeClass
    public void init() throws Exception {
        siblingHash = new TLVElement(false, false, 0x02);
        siblingHash.setDataHashContent(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));

        metadata = new TLVElement(false, false, 0x04);
        TLVElement clientIdElement = new TLVElement(false, false, 0x01);
        clientIdElement.setStringContent("abc");
        metadata.addChildElement(clientIdElement);

        legacyId = new TLVElement(false, false, 0x03);
        legacyId.setContent(LEGACY_ID_CONTENT);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Unsupported level correction amount 257")
    public void testCorrectionLevelExceeds8bits_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x08);
        TLVElement correctionLevel = new TLVElement(false, false, 0x01);
        correctionLevel.setLongContent(257L);
        element.addChildElement(correctionLevel);

        new RightAggregationChainLink(element);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "AggregationChainLink sibling data must consist of one of the following: 'sibling hash', 'legacy id' or 'metadata'")
    public void testLinkMustHaveSiblingHashOrLegacyIdOrMetaData_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x07);
        element.setStringContent("");
        new LeftAggregationChainLink(element);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Multiple sibling data items in hash step. Sibling hash and legacy id are present")
    public void testLinkMustNotHaveSiblingHashAndLegacyId_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x07);
        element.addChildElement(siblingHash);
        element.addChildElement(legacyId);
        new LeftAggregationChainLink(element);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Multiple sibling data items in hash step. Sibling hash and metadata are present")
    public void testLinkMustNotHaveSiblingHashAndMetadata_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x07);
        element.addChildElement(siblingHash);
        element.addChildElement(metadata);
        new LeftAggregationChainLink(element);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Multiple sibling data items in hash step. Legacy id and metadata are present")
    public void testLinkMustNotHaveLegacyIdAndMetadata_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x07);
        element.addChildElement(legacyId);
        element.addChildElement(metadata);
        new LeftAggregationChainLink(element);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "AggregationChainLink metadata does not contain clientId element")
    public void testLinkMetadataDoesNotContainClientId_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement metadata = new TLVElement(false, false, 0x04);
        TLVElement element = new TLVElement(false, false, 0x07);
        element.addChildElement(metadata);
        new LeftAggregationChainLink(element);
    }

    @Test
    public void testDecodeLinkWithMetadata_Ok() throws Exception {
        TLVElement metadata = new TLVElement(false, false, 0x04);
        TLVElement clientId = new TLVElement(false, false, 0x01);
        clientId.setStringContent("abc");
        TLVElement machineId = new TLVElement(false, false, 0x02);
        machineId.setStringContent("123");
        TLVElement sequenceNumber = new TLVElement(false, false, 0x03);
        sequenceNumber.setLongContent(888L);
        TLVElement requestTime = new TLVElement(false, false, 0x04);
        requestTime.setLongContent(new Date().getTime());

        metadata.addChildElement(clientId);
        metadata.addChildElement(machineId);
        metadata.addChildElement(sequenceNumber);
        metadata.addChildElement(requestTime);
        TLVElement element = new TLVElement(false, false, 0x07);
        element.addChildElement(metadata);

        LeftAggregationChainLink link = new LeftAggregationChainLink(element);
        Assert.assertNotNull(link);
        Assert.assertEquals(link.getIdentity(), "abc");
    }

    @Test
    public void testDecodeLinkWithLegacyId_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x08);
        element.addChildElement(legacyId);

        RightAggregationChainLink link = new RightAggregationChainLink(element);
        Assert.assertNotNull(link);
        Assert.assertEquals(link.getIdentity().toLowerCase(), "abc");
    }

    @Test
    public void testCreateNewLeftLink() throws Exception {
        SignatureMetadata metadata = new LinkMetadata("kala");
        LeftAggregationChainLink link = new LeftAggregationChainLink(metadata, 20L);
        Assert.assertEquals(link, new LeftAggregationChainLink(link.getRootElement()));
    }

}
