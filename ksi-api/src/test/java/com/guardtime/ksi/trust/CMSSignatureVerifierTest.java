/*
 * Copyright 2013-2016 Guardtime, Inc.
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

package com.guardtime.ksi.trust;

import com.guardtime.ksi.TestUtil;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

public class CMSSignatureVerifierTest {

    private JKSTrustStore trustStore;
    private CMSSignature mockedSignature;
    private SignerInformationStore signatureStore;

    @BeforeMethod
    public void setUp() throws Exception {
        this.trustStore = new JKSTrustStore("truststore.jks", null);
        this.mockedSignature = Mockito.mock(CMSSignature.class);
        this.signatureStore = Mockito.mock(SignerInformationStore.class);
        Mockito.when(mockedSignature.getSignerInformationStore()).thenReturn(signatureStore);

    }

    @Test(expectedExceptions = InvalidCmsSignatureException.class, expectedExceptionsMessageRegExp = "Invalid CMS signature. Signature does not contain SignerInformation element.")
    public void testVerifySignatureWithoutAnySignerInformationElement_ThrowsInvalidCmsSignatureException() throws Exception {
        Mockito.when(signatureStore.getSigners()).thenReturn(new ArrayList<SignerInformation>());
        CMSSignatureVerifier verifier = new CMSSignatureVerifier(trustStore);
        verifier.verify(mockedSignature);
    }

    @Test(expectedExceptions = InvalidCmsSignatureException.class, expectedExceptionsMessageRegExp = "Invalid CMS signature. Signature contains multiple SingerInformation elements.")
    public void testVerifySignatureWithMultipleSignerInformationElements_ThrowsInvalidCmsSignatureException() throws Exception {
        List<SignerInformation> collection = new ArrayList<SignerInformation>();
        collection.add(null);
        collection.add(null);
        Mockito.when(signatureStore.getSigners()).thenReturn(collection);
        CMSSignatureVerifier verifier = new CMSSignatureVerifier(trustStore);
        verifier.verify(mockedSignature);
    }

    @Test
    public void testVerifySignature_Ok() throws Exception {
        CMSSignature signature = new CMSSignature(TestUtil.loadBytes("cms/signed-data"), TestUtil.loadBytes("cms/cms-signature-ok.pkcs7"));
        CMSSignatureVerifier verifier = new CMSSignatureVerifier(trustStore);
        verifier.verify(signature);
        Assert.assertTrue(true);
    }

    @Test(expectedExceptions = InvalidCmsSignatureException.class, expectedExceptionsMessageRegExp = "Invalid CMS signature.*")
    public void testVerifySignatureUsingInvalidSignedData_ThrowsInvalidCmsSignatureException() throws Exception {
        CMSSignature signature = new CMSSignature(new byte[128], TestUtil.loadBytes("cms/cms-signature-ok.pkcs7"));
        CMSSignatureVerifier verifier = new CMSSignatureVerifier(trustStore);
        verifier.verify(signature);

    }
}