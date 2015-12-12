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

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.unisignature.SignatureData;
import org.testng.Assert;
import org.testng.annotations.Test;

public class SignatureDataTest {

    @Test
    public void testReadSignatureData_Ok() throws Exception {
        InMemorySignatureData data = load("signature-data/signature-data-ok.tlv");
        Assert.assertEquals(data.getElementType(), SignatureData.ELEMENT_TYPE);
        Assert.assertNotNull(data.getSignatureType());
        Assert.assertNotNull(data.getSignatureValue());
        Assert.assertNotNull(data.getCertificateId());
        Assert.assertNull(data.getCertificateRepositoryUri());
    }

    @Test(expectedExceptions = InvalidSignatureDataException.class, expectedExceptionsMessageRegExp = "Signature data signature type can not be null")
    public void testReadSignatureDataWithoutSignatureType_ThrowsInvalidSignatureDataException() throws Exception {
        load("signature-data/signature-data-without-signature-type.tlv");
    }

    @Test(expectedExceptions = InvalidSignatureDataException.class, expectedExceptionsMessageRegExp = "Signature data signature value can not be null")
    public void testReadSignatureDataWithoutSignatureValue_ThrowsInvalidSignatureDataException() throws Exception {
        load("signature-data/signature-data-without-signature-value.tlv");
    }

    @Test(expectedExceptions = InvalidSignatureDataException.class, expectedExceptionsMessageRegExp = "Signature data certificate id can not be null")
    public void testReadSignatureDataWithoutCertificateId_ThrowsInvalidSignatureDataException() throws Exception {
        load("signature-data/signature-data-without-certificate-id.tlv");
    }

    @Test
    public void testReadSignatureDataWithCertificateRepositoryUri_Ok() throws Exception {
        InMemorySignatureData data = load("signature-data/signature-data-with-repository-uri.tlv");
        Assert.assertNotNull(data.getCertificateRepositoryUri());
        Assert.assertEquals(data.getCertificateRepositoryUri(), "http://localhost/rep_uri");
    }

    static InMemorySignatureData load(String file) throws Exception {
        TLVInputStream input = new TLVInputStream(TestUtil.load(file));
        try {
            return new InMemorySignatureData(input.readElement());
        } finally {
            input.close();
        }
    }

}