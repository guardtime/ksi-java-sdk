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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tlv.TLVInputStream;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class PublicationsFilePublicationRecordTest {

    private static final String TEST_FILE_PUBLICATION_RECORD_PUBFILE_OK = "publication-record/publication-record-pubfile-ok.tlv";
    private static final String TEST_FILE_PUBLICATION_RECORD_PUBFILE2_OK = "publication-record/publication-record-pubfile2-ok.tlv";

    @Test
    public void testDecodePublicationFileRecord_Ok() throws Exception {
        PublicationsFilePublicationRecord publicationRecord = load(TestUtil.load(TEST_FILE_PUBLICATION_RECORD_PUBFILE_OK));
        Assert.assertNotNull(publicationRecord.getPublicationData());
        Assert.assertNotNull(publicationRecord.getPublicationData().getPublicationTime());
        Assert.assertEquals(publicationRecord.getPublicationData().getPublicationDataHash(), new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        Assert.assertTrue(publicationRecord.getPublicationReferences().isEmpty());
        Assert.assertTrue(publicationRecord.getPublicationRepositoryURIs().isEmpty());
    }

    @Test
    public void testDecodePublicationsFilePublicationRecordWithReferencesAndRepositoryURI_Ok() throws Exception {
        PublicationsFilePublicationRecord publicationRecord = load(TestUtil.load(TEST_FILE_PUBLICATION_RECORD_PUBFILE2_OK));
        Assert.assertNotNull(publicationRecord.getPublicationData());
        Assert.assertNotNull(publicationRecord.getPublicationData().getPublicationTime());
        Assert.assertEquals(publicationRecord.getPublicationData().getPublicationDataHash(), new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        Assert.assertFalse(publicationRecord.getPublicationReferences().isEmpty());
        Assert.assertEquals(publicationRecord.getPublicationReferences().size(), 2);
        Assert.assertFalse(publicationRecord.getPublicationRepositoryURIs().isEmpty());
        Assert.assertEquals(publicationRecord.getPublicationRepositoryURIs().size(), 2);
    }

    @Test(expectedExceptions = InvalidPublicationRecordException.class, expectedExceptionsMessageRegExp = "Required field publicationData\\(TLV\\[0x10\\]\\) missing in # PublicationRecord TLV\\[0x703\\]")
    public void testDecodePublicationsFilePublicationRecordWithoutPublicationData_ThrowsInvalidPublicationRecordException() throws Exception {
        load(new ByteArrayInputStream(new byte[]{(byte) 0x87, 0x03, 0x0, 0x0}));
    }

    private PublicationsFilePublicationRecord load(InputStream file) throws Exception {
        TLVInputStream input = new TLVInputStream(file);
        try {
            return new PublicationsFilePublicationRecord(input.readElement());
        } finally {
            input.close();
        }
    }

}