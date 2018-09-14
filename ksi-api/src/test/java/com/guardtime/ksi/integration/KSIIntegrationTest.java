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

package com.guardtime.ksi.integration;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.inmemory.PublicationsFilePublicationRecord;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;
import com.guardtime.ksi.util.Base16;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.util.Date;

import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static org.testng.Assert.assertNotNull;

public class KSIIntegrationTest extends AbstractCommonIntegrationTest {

    @Test
    public void testReadUniSignatureFromFile_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.loadFile(SIGNATURE_2017_03_14));
        assertNotNull(signature);
    }

    @Test
    public void testReadUniSignatureFromByteArray_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.loadBytes(SIGNATURE_2017_03_14));
        assertNotNull(signature);
    }

    @Test
    public void testReadUniSignatureFromInputStream_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load(SIGNATURE_2017_03_14));
        assertNotNull(signature);
    }

    @Test
    public void testWriteUniSignatureToOutputStream_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load(SIGNATURE_2017_03_14));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        signature.writeTo(output);
        Assert.assertEquals(signature, ksi.read(output.toByteArray()));
    }

    @Test
    public void testVerifySignatureWithoutContext_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load(SIGNATURE_2017_03_14));
        VerificationResult result = ksi.verify(signature, new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test
    public void testVerifySignatureWithFileDataHashWithoutContext_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load(SIGNATURE_2017_03_14));
        VerificationResult result = ksi.verify(signature, new KeyBasedVerificationPolicy(), new DataHash(
                HashAlgorithm.SHA2_256,
                Base16.decode("11A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")
        ));
        Assert.assertTrue(result.isOk());
    }

    @Test
    public void testVerifyExtendedSignatureWithoutContext_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load(EXTENDED_SIGNATURE_2017_03_14));
        VerificationResult result = ksi.verify(signature, new PublicationsFileBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test
    public void testVerifyExtendedSignatureWithFileHashAndPublicationDataAndWithoutContext_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load(EXTENDED_SIGNATURE_2017_03_14));
        DataHash documentHash = new DataHash(HashAlgorithm.SHA2_256, Base16.decode("11A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"));
        VerificationResult result = ksi.verify(signature, new PublicationsFileBasedVerificationPolicy(), documentHash);
        Assert.assertTrue(result.isOk());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "No suitable publication yet")
    public void testExtendingSignatureWithoutAvailablePublicationRecord_ThrowsKSIException() throws Exception {
        KSISignature signature = ksi.sign("Random Text That Will Be Signed".getBytes());
        ksi.extend(signature);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Publication is before signature")
    public void testExtendingSignatureWithOlderPublicationRecord_ThrowsKSIException() throws Exception {
        KSISignature signature = ksi.sign("Random Text That Will Be Signed".getBytes());
        PublicationData publicationData = new PublicationData(new Date(1410739200000L), new DataHash(
                HashAlgorithm.SHA2_256,
                Base16.decode("C1679EDC2E2A23D1BA9B4F49845C7607AEEF48AD1A344A1572A70907A86FF040")
        ));
        PublicationsFilePublicationRecord publicationRecord = new PublicationsFilePublicationRecord(publicationData);
        ksi.extend(signature, publicationRecord);
    }

}
