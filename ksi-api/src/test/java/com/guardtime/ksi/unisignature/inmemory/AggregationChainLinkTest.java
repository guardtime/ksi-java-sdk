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
import com.guardtime.ksi.util.Base16;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class AggregationChainLinkTest {

    private TLVElement siblingHash;
    private TLVElement metaHash;
    private TLVElement metadata;

    @BeforeClass
    public void init() throws Exception {
        siblingHash = new TLVElement(false, false, 0x02);
        siblingHash.setDataHashContent(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));

        metadata = new TLVElement(false, false, 0x04);
        TLVElement clientIdElement = new TLVElement(false, false, 0x01);
        clientIdElement.setStringContent("abc");
        metadata.addChildElement(clientIdElement);

        metaHash = new TLVElement(false, false, 0x03);
        metaHash.setDataHashContent(new DataHash(HashAlgorithm.SHA2_224, new byte[28]));
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Unsupported level correction amount 257")
    public void testCorrectionLevelExceeds8bits_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x08);
        TLVElement correctionLevel = new TLVElement(false, false, 0x01);
        correctionLevel.setLongContent(257L);
        element.addChildElement(correctionLevel);

        new RightAggregationChainLink(element);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "AggregationChainLink sibling data must consist of one of the following: 'sibling hash', 'meta hash' or 'metadata'")
    public void testLinkMustHaveSiblingHashOrMetaHashOrMetaData_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x07);
        element.setStringContent("");
        new LeftAggregationChainLink(element);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Multiple sibling data items in hash step. Sibling hash and meta hash are present")
    public void testLinkMustNotHaveSiblingHashAndMetaHash_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x07);
        element.addChildElement(siblingHash);
        element.addChildElement(metaHash);
        new LeftAggregationChainLink(element);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Multiple sibling data items in hash step. Sibling hash and metadata are present")
    public void testLinkMustNotHaveSiblingHashAndMetadata_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x07);
        element.addChildElement(siblingHash);
        element.addChildElement(metadata);

        new LeftAggregationChainLink(element);
    }

    @Test(expectedExceptions = InvalidAggregationHashChainException.class, expectedExceptionsMessageRegExp = "Multiple sibling data items in hash step. Meta hash and metadata are present")
    public void testLinkMustNotHaveMetaHashAndMetadata_ThrowsInvalidAggregationHashChainException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x07);
        element.addChildElement(metaHash);
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

        metadata.addChildElement(clientId);
        metadata.addChildElement(machineId);
        TLVElement element = new TLVElement(false, false, 0x07);
        element.addChildElement(metadata);

        LeftAggregationChainLink link = new LeftAggregationChainLink(element);
        Assert.assertNotNull(link);
        Assert.assertEquals(link.getIdentity(), "abc");
    }

    @Test
    public void testDecodeLinkWithMetaHash_Ok() throws Exception {
        TLVElement metaHash = new TLVElement(false, false, 0x03);
        metaHash.setContent(Base16.decode("00:0003414243000000000000000000000000000000"));

        TLVElement element = new TLVElement(false, false, 0x08);
        element.addChildElement(metaHash);

        RightAggregationChainLink link = new RightAggregationChainLink(element);
        Assert.assertNotNull(link);
        Assert.assertEquals(link.getIdentity().toLowerCase(), "abc");
    }

}