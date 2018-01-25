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

package com.guardtime.ksi.publication;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tlv.TLVParserException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Date;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.PUBLICATION_DATA_OK;

public class PublicationDataTest {

    public static final String PUBLICATION_STRING = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";

    @Test
    public void testDecodePublicationData_Ok() throws Exception {
        PublicationData publication = load(TestUtil.load(PUBLICATION_DATA_OK));
        Assert.assertNotNull(publication);
        Assert.assertNotNull(publication.getPublicationTime());
        Assert.assertNotNull(publication.getPublicationDataHash());
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Invalid TLV element. Expected.*")
    public void testDecodeInvalidPublicationData_ThrowsTLVParserException() throws Exception {
        load(new ByteArrayInputStream(new byte[]{0x9, 0x0}));
    }

    @Test(expectedExceptions = InvalidPublicationDataException.class)
    public void testDecodePublicationDataWithoutAnyChildrenElements_ThrowsInvalidPublicationDataEception() throws Exception {
        load(new ByteArrayInputStream(new byte[]{0x10, 0x00}));
    }

    @Test(expectedExceptions = InvalidPublicationDataException.class, expectedExceptionsMessageRegExp = "Publication data publication hash can not be null")
    public void testDecodePublicationDataWithoutPublicationHash_ThrowsInvalidPublicationDataEception() throws Exception {
        load(new ByteArrayInputStream(new byte[]{0x10, 0x02, 0x2, 0x0}));
    }

    @Test(expectedExceptions = InvalidPublicationDataException.class, expectedExceptionsMessageRegExp = "Publication data publication time can not be null")
    public void testDecodePublicationDataWithoutPublicationTime_ThrowsInvalidPublicationDataEception() throws Exception {
        load(new ByteArrayInputStream(new byte[]{0x10, 0x02, 0x4, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}));
    }

    @Test
    public void testCreatePublicationData_Ok() throws Exception {
        PublicationData publicationData = new PublicationData(new Date(1000L), new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        publicationData.writeTo(out);
        Assert.assertEquals(out.toByteArray(), new byte[]{0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x21, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0});
        Assert.assertEquals(publicationData.getPublicationDataHash(), new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        Assert.assertEquals(publicationData.getPublicationTime().getTime(), 1000L);
    }

    @Test(expectedExceptions = InvalidPublicationDataException.class, expectedExceptionsMessageRegExp = "Publication data publication time can not be null")
    public void testCreatePublicationDataWithoutPublicationTime_ThrowsInvalidPublicationDataEception() throws Exception {
        new PublicationData(null, new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
    }

    @Test(expectedExceptions = InvalidPublicationDataException.class, expectedExceptionsMessageRegExp = "Publication data publication hash can not be null")
    public void testCreatePublicationDataWithoutPublicationHash_ThrowsInvalidPublicationDataEception() throws Exception {
        new PublicationData(new Date(1000L), null);
    }

    @Test(expectedExceptions = InvalidPublicationDataException.class, expectedExceptionsMessageRegExp = "Publication data publication string can not be null")
    public void testCreatePublicationDataUsingInvalidPublicationString_ThrowsInvalidPublicationDataEception() throws Exception {
        new PublicationData((String) null);
    }

    @Test(expectedExceptions = InvalidPublicationDataException.class, expectedExceptionsMessageRegExp = "Invalid publication string: Base32 decode failed")
    public void testCreatePublicationDataUsingInvalidEncodedPublicationString_ThrowsInvalidPublicationDataEception() throws Exception {
        new PublicationData("NN2WW2LNOVVWS===");
    }

    @Test(expectedExceptions = InvalidPublicationDataException.class, expectedExceptionsMessageRegExp = "Invalid publication string: CRC32 Check failed")
    public void testCreatePublicationDataUsingInvalidPublicationStringCRC32_ThrowsInvalidPublicationDataException() throws Exception {
        new PublicationData("GEZTSOBRGU2DQNRUJ5GEKTSJJRKVGSCBKNEEGUSDGMZA====");
    }

    @Test
    public void testCreatePublicationDataUsingPublicationString_Ok() throws Exception {
        PublicationData publicationData = new PublicationData(PUBLICATION_STRING);
        Assert.assertEquals(publicationData.getPublicationString(), PUBLICATION_STRING);
    }

    private PublicationData load(InputStream input) throws Exception {
        return new PublicationData(loadTlv(input));
    }

}