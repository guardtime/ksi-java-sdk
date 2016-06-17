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

package com.guardtime.ksi.tlv;

import com.guardtime.ksi.CommonTestUtil;
import com.guardtime.ksi.util.Util;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FileInputStream;

public class TLVInputStreamTest {

    private TLVInputStream input;

    @AfterMethod
    public void clean() {
        Util.closeQuietly(input);
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Input stream is null")
    public void testCreateTlvInputStreamWithInvalidInput_ThrowsTLVParserException() throws Exception {
        input = new TLVInputStream(null);
    }

    @Test
    public void testCreateTlvInputStreamUsingNonBufferedStream_Ok() throws Exception {
        input = new TLVInputStream(new FileInputStream("pom.xml"));
    }

    @Test
    public void testReadTlv8Element_Ok() throws Exception {
        input = new TLVInputStream(new ByteArrayInputStream(new byte[]{1, 4, 4, 2, 1, 0}));
        Assert.assertTrue(input.hasNextElement());
        TLVElement tlvElement = input.readElement();
        Assert.assertFalse(tlvElement.isOutputTlv16());
        Assert.assertFalse(tlvElement.isForwarded());
        Assert.assertFalse(tlvElement.isNonCritical());
        Assert.assertEquals(tlvElement.getContent().length, 4);
        Assert.assertEquals(new byte[]{4, 2, 1, 0}, tlvElement.getContent());
    }

    @Test
    public void testReadTlv8ElementContainingUnknownFlag_Ok() throws Exception {
        input = new TLVInputStream(new ByteArrayInputStream(new byte[]{(byte) (1 << 6) + 1, 4, 4, 2, 1, 0}));

        Assert.assertTrue(input.hasNextElement());
        TLVElement tlvElement = input.readElement();
        Assert.assertFalse(tlvElement.isOutputTlv16());
        Assert.assertFalse(tlvElement.isForwarded());
        Assert.assertTrue(tlvElement.isNonCritical());
        Assert.assertEquals(tlvElement.getContent().length, 4);
        Assert.assertEquals(new byte[]{4, 2, 1, 0}, tlvElement.getContent());
    }

    @Test
    public void testReadTlv8ElementContainingForwardedFlag_Ok() throws Exception {
        input = new TLVInputStream(new ByteArrayInputStream(new byte[]{(byte) (3 << 5) + 1, 4, 4, 2, 1, 0}));

        Assert.assertTrue(input.hasNextElement());
        TLVElement tlvElement = input.readElement();
        Assert.assertFalse(tlvElement.isOutputTlv16());
        Assert.assertTrue(tlvElement.isForwarded());
        Assert.assertTrue(tlvElement.isNonCritical());
        Assert.assertEquals(tlvElement.getContent().length, 4);
        Assert.assertEquals(new byte[]{4, 2, 1, 0}, tlvElement.getContent());
    }

    @Test
    public void testReadTlv16Element_Ok() throws Exception {
        input = new TLVInputStream(new ByteArrayInputStream(new byte[]{(byte) (1 << 7), 0x20, 0, 2, 1, 2}));

        Assert.assertTrue(input.hasNextElement());
        TLVElement tlvElement = input.readElement();
        Assert.assertTrue(tlvElement.isOutputTlv16());
        Assert.assertFalse(tlvElement.isForwarded());
        Assert.assertFalse(tlvElement.isNonCritical());
        Assert.assertEquals(tlvElement.getContent().length, 2);
        Assert.assertEquals(new byte[]{1, 2}, tlvElement.getContent());
    }

    @Test(expectedExceptions = EOFException.class)
    public void testReadTlvElementFromEmptyStream() throws Exception {
        input = new TLVInputStream(new ByteArrayInputStream(new byte[]{}));
        input.readElement();
    }

    @Test
    public void testReadTlv16ElementContainingNestedElements_Ok() throws Exception {
        input = new TLVInputStream(CommonTestUtil.load("aggregation-203-error.tlv"));
        int count = 0;
        while (input.hasNextElement()) {
            input.readElement();
            count++;
        }
        Assert.assertEquals(1, count);
    }

    @Test (expectedExceptions = EOFException.class)
    public void testReadCorrectPublication_EOFException() throws Exception {
        input = new TLVInputStream(CommonTestUtil.load("publications-file.tlv"));
        while (input.hasNextElement()) { input.readElement();}
    }

    @Test
    public void testReadPublicationFile_OK() throws Exception {
        input = new TLVInputStream(CommonTestUtil.load("publications-file-no-magic.tlv"));
        int countOfTlvElements = 0;
        while (input.hasNextElement()) {
            TLVElement element = input.readElement();
            Assert.assertFalse(element == null);
            countOfTlvElements++;
        }
        Assert.assertEquals(87, countOfTlvElements);
    }
}
