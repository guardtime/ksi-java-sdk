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

package com.guardtime.ksi.publication.inmemory;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.tlv.TLVParserException;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.util.Date;

import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CERT_AND_PUBLICATION_RECORD_MISSING;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_CERT;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_HEADER;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD2;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN_WITH_NON_CIRITCAL_ELEMENTS;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_HAS_CRITICAL_ELEMENT;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_HAS_UNKNOWN_ELEMENT;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_HEADER_MISSING;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_INVALID_HASH_LENGTH;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_MULTI_HEADER;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN_WITH_CIRITCAL_ELEMENTS;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_REFERENCE_AFTER_SIGNATURE;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_REORDERED;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_SIGANTURE_MISSING;

public class InMemoryPublicationsFileTest {


    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "InputStream can not be null when creating publications file")
    public void testCreatePublicationsFileUsingInvalidInputStream_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(null);
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file magic bytes")
    public void testCreatePublicationsFileUsingInvalidMagicBytes_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(new ByteArrayInputStream(new byte[]{0x4b, 0x53, 0x49, 0x50, 0x55, 0x42, 0x4c, 0x47}));
    }

    @Test
    public void testCreatePublicationsFile_Ok() throws Exception {
        InMemoryPublicationsFile publication = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE));
        Assert.assertNotNull(publication.getVersion());
        Assert.assertNotNull(publication.getCreationTime());
        Assert.assertNull(publication.getRepositoryUri());
        Assert.assertNotNull(publication.getPublicationRecords());
        Assert.assertFalse(publication.getPublicationRecords().isEmpty());
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = ".*Publications file header is missing")
    public void testCreatePublicationsFileWithoutHeader_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_HEADER_MISSING));
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = ".*Publications file CMS signature is missing")
    public void testCreatePublicationsFileWithoutCmsSignature_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_SIGANTURE_MISSING));
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = ".*Publications file order is incorrect")
    public void testCreatePublicationsFileWithIncorrectElementOrder_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_REORDERED));
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = ".*Publications file order is incorrect")
    public void testCreatePublicationsFileWithElementAfterSignature_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_REFERENCE_AFTER_SIGNATURE));
    }

    @Test
    public void testCreatePublicationsFileWithoutCertificateAndPublicationRecords_Ok() throws Exception {
        PublicationsFile publicationFile = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_CERT_AND_PUBLICATION_RECORD_MISSING));
        Assert.assertNotNull(publicationFile);
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x2")
    public void testCreatePublicationsFileWithUnknownElement_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_HAS_UNKNOWN_ELEMENT));
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x2")
    public void testCreatePublicationsFileWithCriticalUnknownElement_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_HAS_CRITICAL_ELEMENT));
    }

    @Test
    public void testGetCertificateFromPublicationsFile_Ok() throws Exception {
        PublicationsFile publication = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE));
        Assert.assertNotNull(publication.findCertificateById(new byte[]{-102, 101, -126, -108}));
    }

    @Test(expectedExceptions = CertificateNotFoundException.class, expectedExceptionsMessageRegExp = "Certificate with id AAAAAAAAAAAAAAAAAAAAAAAAAA== not found from pubFile=.*")
    public void testGetUnknownCertificateFromPublicationsFile_ThrowsCertificateNotFoundException() throws Exception {
        PublicationsFile publication = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE));
        publication.findCertificateById(new byte[19]);
    }

    @Test(expectedExceptions = CertificateNotFoundException.class, expectedExceptionsMessageRegExp = "Certificate with id null not found from pubFile=.*")
    public void testGetCertificateFromPublicationsFileUsingInvalidCertificateId_ThrowsCertificateNotFoundException() throws Exception {
        PublicationsFile publication = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE));
        publication.findCertificateById(null);
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Publications file contains multiple header components")
    public void testDecodePublicationsFileWithTwoHeaders_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_MULTI_HEADER));
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Invalid DataHash content")
    public void testDecodePublicationsFileWithInvalidHashLength_ThrowsTLVParserException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_INVALID_HASH_LENGTH));
    }

    @Test
    public void testVerifyThatActualLatestPublicationRecordIsFound_OK() throws Exception {
        PublicationsFile publication = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE));
        PublicationData latest = publication.getLatestPublication().getPublicationData();
        Assert.assertEquals(latest, publication.getPublicationRecord(new Date(latest.getPublicationTime().getTime() - 100000L)).getPublicationData());
        Assert.assertNull(publication.getPublicationRecord(new Date(latest.getPublicationTime().getTime() + 1000L)));
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x1 encountered")
    public void testDecodePublicationsFileWithUnknownCriticalElementInRecord() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD));
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x5 encountered")
    public void testDecodePublicationsFileWithUnknownCriticalElementInRecord2() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD2));
    }
    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testDecodePublicationsFileWithUnknownCriticalNestedTlv() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN));
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testDecodePublicationsFileWithUnknownCriticalNestedTlvWithNonCriticalChild() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN_WITH_NON_CIRITCAL_ELEMENTS));
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testDecodePublicationsFileWithUnknownNonCriticalElementInMain() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN));
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testDecodePublicationsFileWithNonCriticalNestedTlvWithCriticalChild() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN_WITH_CIRITCAL_ELEMENTS));
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x5 encountered")
    public void testDecodePublicationsFileWithCriticalElementInCertificateRecord() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_CERT));
    }

    @Test(expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x5 encountered")
    public void testDecodePublicationsFileWithCriticalElementInPublicationHeader() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_HEADER));
    }
}