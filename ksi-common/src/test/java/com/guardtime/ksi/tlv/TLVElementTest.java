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

package com.guardtime.ksi.tlv;

import com.guardtime.ksi.CommonTestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.testng.reporters.Files;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Date;
import java.util.List;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;

public class TLVElementTest {

    @Test
    public void testGetTheFirstChildElementFromNestedTlvElement_Ok() throws Exception {
        TLVElement element = load(CommonTestUtil.load("aggregation-203-error.tlv"));
        Assert.assertNotNull(element.getFirstChildElement(0x203));
        Assert.assertNull(element.getFirstChildElement(0x202));
    }

    @Test
    public void testGetAllTheChildElementsFormEncodeTlvElement_Ok() throws Exception {
        TLVElement element = load(CommonTestUtil.load("aggregation-203-error.tlv"));
        List<TLVElement> childElements = element.getChildElements(0x203);
        Assert.assertNotNull(childElements);
        Assert.assertEquals(childElements.size(), 1);
        Assert.assertTrue(element.getChildElements(0x202).isEmpty());
    }

    @Test
    public void testEncodeTlv16ElementWithoutData_Ok() throws Exception {
        TLVElement element = new TLVElement(true, true, 0x0202);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);

        element = load(new ByteArrayInputStream(out.toByteArray()));
        Assert.assertEquals(element.getType(), 0x0202);
        Assert.assertTrue(element.isOutputTlv16());
        Assert.assertTrue(element.isForwarded());
        Assert.assertTrue(element.isNonCritical());
    }

    @Test
    public void testEncodeTlv16ElementWithData_Ok() throws Exception {
        TLVElement element = new TLVElement(true, true, 0x0202);
        element.setStringContent("OK");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);

        element = load(new ByteArrayInputStream(out.toByteArray()));
        Assert.assertEquals(element.getType(), 0x0202);
        Assert.assertTrue(element.isOutputTlv16());
        Assert.assertTrue(element.isForwarded());
        Assert.assertTrue(element.isNonCritical());
        Assert.assertEquals(element.getDecodedString(), "OK");
    }

    @Test
    public void testEncodeStringElement_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 2);
        element.setStringContent("OK");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);
        Assert.assertEquals(out.toByteArray(), new byte[]{0x02, 0x03, 'O', 'K', 0x0});
    }

    @Test
    public void testEncodeElementContainingEmptyString_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 2);
        element.setStringContent(null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);
        Assert.assertEquals(out.toByteArray(), new byte[]{0x02, 0x01, 0x0});
    }

    @Test
    public void testDecodeTlvElementContainingStringValue_Ok() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x02, 0x03, 'O', 'K', 0x0}));
        Assert.assertEquals(element.getType(), 2);
        Assert.assertFalse(element.isOutputTlv16());
        Assert.assertFalse(element.isForwarded());
        Assert.assertFalse(element.isNonCritical());
        Assert.assertEquals(element.getDecodedString(), "OK");
    }

    @Test
    public void testDecodeTlvElementContainingEmptyStringValue_Ok() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x02, 0x01, 0x0}));
        Assert.assertEquals(element.getType(), 2);
        Assert.assertFalse(element.isOutputTlv16());
        Assert.assertFalse(element.isForwarded());
        Assert.assertFalse(element.isNonCritical());
        Assert.assertEquals(element.getDecodedString(), "");
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "String must be null terminated")
    public void testDecodeInvalidStringTlvElement_ThrowsTLVParserException() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x02, 0x02, 'O', 'K'}));
        element.getDecodedString();
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "String must be null terminated")
    public void testDecodeInvalidStringElement_ThrowsTLVParserException() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x02, 0x00}));
        element.getDecodedString();
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Malformed UTF-8 data")
    public void testDecodeInvalidNonUTF8StringElement_ThrowsTLVParserException() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x02, 0x05, (byte) 0xfe, (byte) 0xff, 0x0e, 0x22, 0x0}));
        element.getDecodedString();
    }

    @Test
    public void testDecodeIntegerElement_Ok() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x2, 0x1, 0x1}));
        Assert.assertEquals(element.getDecodedLong().longValue(), 1, "Value should be preserved");
        Assert.assertEquals(element.getType(), 2, "Type should be preserved");
    }

    @Test
    public void testDecodeIntegerZeroElement_Ok() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x2, 0x0}));
        Assert.assertEquals(element.getDecodedLong().longValue(), 0, "Value should be preserved");
        Assert.assertEquals(element.getType(), 2, "Type should be preserved");
    }

    @Test
    public void testDecodeElementWithMaximumInteger_Ok() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x2, 0x8, 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff}));
        Assert.assertEquals(element.getDecodedLong().longValue(), 0x7fffffffffffffffL, "Value should be preserved");
        Assert.assertEquals(element.getType(), 2, "Type should be preserved");
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Integer encoding cannot contain leading zeros")
    public void testDecodeIntegerWithLeadingZeroes_ThrowsTLVParserException() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x2, 0x3, 0x0, 0x0, 0x0}));
        element.getDecodedLong();
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Integers of at most 63 unsigned bits supported by this implementation")
    public void testDecodeElementContainingIntegerOverflow_ThrowsTLVParserException() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x2, 0x8, (byte) 0x80, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}));
        element.getDecodedLong();
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Integers of at most 63 unsigned bits supported by this implementation")
    public void testDecodeElementContainingIntegerOverflow2_ThrowsTLVParserException() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x2, 0x9, (byte) 0x80, (byte) 0x80, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}));
        element.getDecodedLong();
    }

    @Test
    public void testDecodeElementHighBit_Ok() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x2, 0x2, (byte) 0xff, (byte) 0xff}));
        Assert.assertEquals(element.getDecodedLong().longValue(), 0xffff, "Value should be preserved");
        Assert.assertEquals(element.getType(), 2, "Type should be preserved");
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Only non-negative integer values are allowed")
    public void testCreateTLVElementContainingNegativeInteger_ThrowsIllegalArgumentException() throws Exception {
        TLVElement element = new TLVElement(false, false, 2);
        element.setLongContent(-1);
    }

    @Test
    public void testEncodeTLVIntegerElement_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 2);
        element.setLongContent(0xffffffffL);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);

        Assert.assertEquals(out.toByteArray(), new byte[]{0x02, 0x04, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
    }

    @Test
    public void testEncodeTLVIntegerZeroElement_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 2);
        element.setLongContent(0);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);

        Assert.assertEquals(out.toByteArray(), new byte[]{0x02, 0x00});
    }

    @Test
    public void testDecodeImprintTlvElement_Ok() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(
                new byte[]{0x2, 21, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}));
        Assert.assertEquals(element.getDecodedDataHash().getAlgorithm(), HashAlgorithm.RIPEMD_160, "Algorithm should be parsed correctly");
        Assert.assertEquals(element.getDecodedDataHash().getValue(), new byte[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                "Hash Value should be parsed correctly");
        Assert.assertEquals(element.getType(), 2, "Type should be preserved");
    }

    @Test
    public void testEncodeImprintTlvElement_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 2);
        element.setDataHashContent(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);
        Assert.assertEquals(out.toByteArray(), new byte[]{0x2, 33, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Invalid DataHash content")
    public void testDecodeTlvElementContainingUnknownHashAlgorithm_ThrowsTLVParserException() throws Exception {
        TLVElement element = load(new ByteArrayInputStream(new byte[]{0x2, 21, 112, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}));
        element.getDecodedDataHash();
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Hash size\\(31\\) does not match SHA-256 size\\(32\\)")
    public void testCreateTlvElementWithWrongImprintLength_ThrowsFormatException() throws Exception {
        TLVElement element = new TLVElement(false, false, 2);
        element.setDataHashContent(new DataHash(HashAlgorithm.SHA2_256, new byte[31]));
    }

    @Test
    public void testWritingOutNotUsedId_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x0f);
        element.setDataHashContent(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);
        Assert.assertEquals(out.toByteArray(), new byte[]{0x0f, 33, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    }

    @Test
    public void testCreateTlvElementFromOkBytes_OK() throws Exception {
        TLVElement element = TLVElement.create(new byte[]{0x0f, 33, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);
        Assert.assertEquals(out.toByteArray(), new byte[]{0x0f, 33, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Reading TLV bytes failed")
    public void testCreateTlvElementFromNokBytes_ExpectedTlvParserException() throws Exception {
        TLVElement.create(new byte[]{0x0, 2, 0x0});
    }

    @Test(expectedExceptions = MultipleTLVElementException.class, expectedExceptionsMessageRegExp = "Message outermost layer consists of more than one TLV elements.")
    public void TestCreateTlvElementFromNokBytes_ExpectedMultipleTlvElementException() throws Exception {
        TLVElement.create(new byte[]{0, 0, 0});
    }

    @Test
    public void testGetDecodedHashAlgorithm_OK() throws Exception {
        TLVElement element = TLVElement.create(new byte[]{0x0f, 33, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        element.setLongContent(0x0A);
        Assert.assertEquals(element.getDecodedHashAlgorithm(), HashAlgorithm.SHA3_512);
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown hash algorithm with id 255")
    public void testGetDecodedHashAlgorithm_UnknownHashAlgorithm() throws Exception {
        TLVElement element = TLVElement.create(new byte[]{0x0f, 33, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        element.setLongContent(0xFF);
        element.getDecodedHashAlgorithm();
    }

    @Test
    public void testGetDecodedDate_OK() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x1);
        element.setLongContent(1442837678);
        Assert.assertEquals(element.getDecodedDate(), new Date(1442837678000L));
    }

    @Test(expectedExceptions = MultipleTLVElementException.class)
    public void testCreateTlvElementFromTooLargeInput_ThrowsMultipleTLVElementException() throws Exception {
        byte[] tmp = Files.readFile(CommonTestUtil.loadFile("root_content_larger_than_max.tlv")).getBytes();
        TLVElement.create(tmp);
    }

    @Test
    public void testTlvWithLongTypeIsAlwaysEncodedAsTlv16() {
        TLVElement element = new TLVElement(false, false, 0x800);
        Assert.assertTrue(element.isOutputTlv16());
    }

    @Test
    public void testCreateShortTlv8_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x05);
        element.setContent(new byte[200]);
        Assert.assertFalse(element.isOutputTlv16());
        Assert.assertEquals(200, element.getContentLength());
        Assert.assertEquals(2, element.getHeaderLength());
    }

    @Test
    public void testCreateShortTlv16_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x05);
        element.setContent(new byte[257]);
        Assert.assertTrue(element.isOutputTlv16());
        Assert.assertEquals(257, element.getContentLength());
        Assert.assertEquals(4, element.getHeaderLength());
    }

    @Test
    public void testCreateTlvElementWithMaximumContentLength_Ok() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x1);
        element.setContent(new byte[TLVElement.MAX_TLV16_CONTENT_LENGTH]);
        Assert.assertTrue(element.isOutputTlv16());
        Assert.assertEquals(TLVElement.MAX_TLV16_CONTENT_LENGTH, element.getContentLength());
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "TLV16 should never contain more than 65535 bytes of content,.*")
    public void testCreateTlvElementWithTooLargeContent_ThrowsTLVParserException() throws Exception {
        TLVElement element = new TLVElement(false, false, 0x1);
        element.setContent(new byte[TLVElement.MAX_TLV16_CONTENT_LENGTH + 1]);
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "TLV16 should never contain more than 65535 bytes of content,.*")
    public void testCreateTlvElementWithTooLargeChildrenContent_testCreateTlvElementWithTooLargeContent_ThrowsTLVParserException() throws Exception {
        TLVElement root = new TLVElement(false, false, 0x1);
        TLVElement child1 = new TLVElement(false, false, 0x02);
        child1.setContent(new byte[TLVElement.MAX_TLV16_CONTENT_LENGTH - 10]);
        TLVElement child2 = new TLVElement(false, false, 0x03);
        child2.setContent(new byte[9]);
        root.addChildElement(child1);
        root.addChildElement(child2);
    }

    private TLVElement load(InputStream input) throws Exception {
        return loadTlv(input);
    }

}
