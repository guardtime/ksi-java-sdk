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

package com.guardtime.ksi.publication.inmemory;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.publication.PublicationsFile;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;

public class InMemoryPublicationsFileTest {

    public static final String PUBLICATIONS_FILE_OK = "publications.tlv";
    public static final String PUBLICATIONS_FILE_HEADER_MISSING = "publications-file/publications-file-header-missing.tlv";
    public static final String PUBLICATIONS_FILE_SIGNATURE_MISSING = "publications-file/publications-file-signature-missing.tlv";
    public static final String PUBLICATIONS_FILE_CONTAINS_UNKNOWN_ELEMENT = "publications-file/publications-file-contains-unknown-element.tlv";
    public static final String PUBLICATIONS_FILE_CONTAINS_CRITICAL_UNKNOWN_ELEMENT = "publications-file/publications-file-contains-critical-unknown-element.tlv";

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
        InMemoryPublicationsFile publication = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_OK));
        Assert.assertNotNull(publication.getVersion());
        Assert.assertNotNull(publication.getCreationTime());
        Assert.assertNull(publication.getRepositoryUri());
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = ".*Publications file header is missing")
    public void testCreatePublicationsFileWithoutHeader_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_HEADER_MISSING));
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = ".*Publications file CMS signature is missing")
    public void testCreatePublicationsFileWithoutCmsSignature_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_SIGNATURE_MISSING));
    }

    @Test
    public void testCreatePublicationsFileWithoutCertificateAndPublicationRecords_Ok() throws Exception {
        PublicationsFile publicationFile = new InMemoryPublicationsFile(TestUtil.load("publications-file/publications-file-cert-and-pub-records-missing.tlv"));
        Assert.assertNotNull(publicationFile);
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x2")
    public void testCreatePublicationsFileWithUnknownElement_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_CONTAINS_UNKNOWN_ELEMENT));
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x2")
    public void testCreatePublicationsFileWithCriticalUnknownElement_ThrowsInvalidPublicationsFileException() throws Exception {
        new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_CONTAINS_CRITICAL_UNKNOWN_ELEMENT));
    }

    @Test
    public void testGetCertificateFromPublicationsFile_Ok() throws Exception {
        PublicationsFile publication = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_OK));
        Assert.assertNotNull(publication.findCertificateById(new byte[]{-102, 101, -126, -108}));
    }

    @Test(expectedExceptions = CertificateNotFoundException.class, expectedExceptionsMessageRegExp = "Certificate with id AAAAAAAAAAAAAAAAAAAAAAAAAA== not found from pubFile=.*")
    public void testGetUnknownCertificateFromPublicationsFile_ThrowsCertificateNotFoundException() throws Exception {
        PublicationsFile publication = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_OK));
        publication.findCertificateById(new byte[19]);
    }

    @Test(expectedExceptions = CertificateNotFoundException.class, expectedExceptionsMessageRegExp = "Certificate with id null not found from pubFile=.*")
    public void testGetCertificateFromPublicationsFileUsingInvalidCertificateId_ThrowsCertificateNotFoundException() throws Exception {
        PublicationsFile publication = new InMemoryPublicationsFile(TestUtil.load(PUBLICATIONS_FILE_OK));
        publication.findCertificateById(null);
    }

}