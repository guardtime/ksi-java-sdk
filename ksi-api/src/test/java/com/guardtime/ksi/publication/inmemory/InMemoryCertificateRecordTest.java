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
import com.guardtime.ksi.tlv.TLVInputStream;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class InMemoryCertificateRecordTest {

    private static final String TEST_FILE_CERTIFICATE_RECORD = "certificate-record/certificate-record-ok.tlv";
    private static final String TEST_FILE_CERTIFICATE_RECORD_MISSING_CERTIFICATE_ID = "certificate-record/certificate-record-missing-certificate-id.tlv";
    private static final String TEST_FILE_CERTIFICATE_RECORD_MISSING_CERTIFICATE = "certificate-record/certificate-record-missing-certificate.tlv";

    @Test
    public void testDecodeCertificateRecord_Ok() throws Exception {
        InMemoryCertificateRecord certificateRecord = load(TEST_FILE_CERTIFICATE_RECORD);
        assertNotNull(certificateRecord.getCertificate());
        assertNotNull(certificateRecord.getCertificateId());
        assertEquals(certificateRecord.getCertificateId(), new byte[]{1, 2, 3, 4});
        assertEquals(certificateRecord.getCertificate(), new byte[]{1, 1, 1, 1});
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Certificate Id can not be null")
    public void testDecodeCertificateRecordWithoutCertificateId_ThrowsInvalidPublicationsFileException() throws Exception {
        load(TEST_FILE_CERTIFICATE_RECORD_MISSING_CERTIFICATE_ID);
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Certificate can not be null")
    public void testDecodeCertificateRecordWithoutCertificate_ThrowsInvalidPublicationsFileException() throws Exception {
        load(TEST_FILE_CERTIFICATE_RECORD_MISSING_CERTIFICATE);
    }

    private InMemoryCertificateRecord load(String file) throws Exception {
        TLVInputStream input = new TLVInputStream(TestUtil.load(file));
        try {
            return new InMemoryCertificateRecord(input.readElement());
        } finally {
            input.close();
        }
    }

}