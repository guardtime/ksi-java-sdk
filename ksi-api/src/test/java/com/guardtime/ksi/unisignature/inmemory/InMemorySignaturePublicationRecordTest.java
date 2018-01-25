/*
 * Copyright 2013-2017 Guardtime, Inc.
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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.inmemory.InvalidPublicationRecordException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.PUBLICATION_RECORD_IN_SIGNATURE_OK;
import static com.guardtime.ksi.Resources.PUBLICATION_RECORD_WITH_REF_AND_REPO_URI_IN_SIGNATURE_OK;

public class InMemorySignaturePublicationRecordTest {

    @Test
    public void testDecodeInMemorySignaturePublicationRecord_Ok() throws Exception {
        InMemorySignaturePublicationRecord publicationRecord = load(TestUtil.load(PUBLICATION_RECORD_IN_SIGNATURE_OK));
        Assert.assertNotNull(publicationRecord.getPublicationData());
        Assert.assertNotNull(publicationRecord.getPublicationData().getPublicationTime());
        Assert.assertEquals(publicationRecord.getPublicationData().getPublicationDataHash(), new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        Assert.assertTrue(publicationRecord.getPublicationReferences().isEmpty());
        Assert.assertTrue(publicationRecord.getPublicationRepositoryURIs().isEmpty());
    }

    @Test
    public void testDecodeInMemorySignaturePublicationRecordWithReferencesAndRepositoryURI_Ok() throws Exception {
        InMemorySignaturePublicationRecord publicationRecord = load(TestUtil.load(PUBLICATION_RECORD_WITH_REF_AND_REPO_URI_IN_SIGNATURE_OK));
        Assert.assertNotNull(publicationRecord.getPublicationData());
        Assert.assertNotNull(publicationRecord.getPublicationData().getPublicationTime());
        Assert.assertEquals(publicationRecord.getPublicationData().getPublicationDataHash(), new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        Assert.assertFalse(publicationRecord.getPublicationReferences().isEmpty());
        Assert.assertEquals(publicationRecord.getPublicationReferences().size(), 3);
        Assert.assertFalse(publicationRecord.getPublicationRepositoryURIs().isEmpty());
        Assert.assertEquals(publicationRecord.getPublicationRepositoryURIs().size(), 4);
    }

    @Test(expectedExceptions = InvalidPublicationRecordException.class, expectedExceptionsMessageRegExp = "Required field publicationData\\(TLV\\[0x10\\]\\) missing in # PublicationRecord TLV\\[0x803\\]")
    public void testDecodeInMemorySignaturePublicationRecordWithoutPublicationData_ThrowsInvalidPublicationRecordException() throws Exception {
        load(new ByteArrayInputStream(new byte[]{(byte) 0x88, 0x03, 0x0, 0x0}));
    }

    private InMemorySignaturePublicationRecord load(InputStream file) throws Exception {
        return new InMemorySignaturePublicationRecord(loadTlv(file));
    }

}