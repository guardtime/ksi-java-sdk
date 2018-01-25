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

package com.guardtime.ksi.publication.inmemory;

import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.CERTIFICATE_RECORD_MISSING_CERT;
import static com.guardtime.ksi.Resources.CERTIFICATE_RECORD_MISSING_CERT_ID;
import static com.guardtime.ksi.Resources.CERTIFICATE_RECORD_OK;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class InMemoryCertificateRecordTest {

    @Test
    public void testDecodeCertificateRecord_Ok() throws Exception {
        InMemoryCertificateRecord certificateRecord = load(CERTIFICATE_RECORD_OK);
        assertNotNull(certificateRecord.getCertificate());
        assertNotNull(certificateRecord.getCertificateId());
        assertEquals(certificateRecord.getCertificateId(), new byte[]{1, 2, 3, 4});
        assertEquals(certificateRecord.getCertificate(), new byte[]{1, 1, 1, 1});
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Certificate Id can not be null")
    public void testDecodeCertificateRecordWithoutCertificateId_ThrowsInvalidPublicationsFileException() throws Exception {
        load(CERTIFICATE_RECORD_MISSING_CERT_ID);
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Certificate can not be null")
    public void testDecodeCertificateRecordWithoutCertificate_ThrowsInvalidPublicationsFileException() throws Exception {
        load(CERTIFICATE_RECORD_MISSING_CERT);
    }

    private InMemoryCertificateRecord load(String file) throws Exception {
        return new InMemoryCertificateRecord(loadTlv(file));
    }

}