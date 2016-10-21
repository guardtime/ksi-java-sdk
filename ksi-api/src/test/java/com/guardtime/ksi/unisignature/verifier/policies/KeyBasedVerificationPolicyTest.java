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

package com.guardtime.ksi.unisignature.verifier.policies;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.inmemory.CertificateNotFoundException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.verifier.rules.CalendarAuthenticationRecordExistenceRule;
import com.guardtime.ksi.unisignature.verifier.rules.Rule;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Map;

import static com.guardtime.ksi.TestUtil.loadFile;

public class KeyBasedVerificationPolicyTest {

    private KSI ksi;
    private KSIExtenderClient mockedExtenderClient;

    @BeforeMethod
    public void setUp() throws Exception {
        mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);
        Mockito.when(mockedExtenderClient.getPduVersion()).thenReturn(PduVersion.V1);
        KSIPublicationsFileClient mockedPublicationFileClient = Mockito.mock(KSIPublicationsFileClient.class);
        KSISigningClient mockerSigningClient = Mockito.mock(KSISigningClient.class);
        Mockito.when(mockerSigningClient.getPduVersion()).thenReturn(PduVersion.V1);
        CertSelector mockedCertificateSelector = Mockito.mock(CertSelector.class);
        Mockito.when(mockedCertificateSelector.match(Mockito.any(Certificate.class))).thenReturn(Boolean.TRUE);
        ksi = new KSIBuilder().setKsiProtocolExtenderClient(mockedExtenderClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationFileClient).
                setKsiProtocolSignerClient(mockerSigningClient).
                setPublicationsFileTrustedCertSelector(mockedCertificateSelector).
                build();
    }

    @Test
    public void testCreateNewKeyBasedVerificationPolicy_Ok() throws Exception {
        KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy();
        Assert.assertNotNull(policy.getRules());
        Assert.assertNotNull(policy.getName());
        Assert.assertFalse(policy.getRules().isEmpty());
        Assert.assertNotNull(policy.getType());
    }

    @Test
    public void testVerifySignatureOfflineWithInvalidAuthenticationRecord_ThrowsVerificationException() throws Exception {
        PublicationsFile mockedTrustProvider = Mockito.mock(PublicationsFile.class);
        KSISignature signature = TestUtil.loadSignature("not-ok-sig-2014-04-30.1-extended.ksig");

        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, mockedExtenderClient, TestUtil.getFileHash(loadFile("infile"), "SHA2-256"), mockedTrustProvider), new KeyBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.INT_09);
    }

    @Test
    public void testVerifySignatureWithoutCalendarAuthenticationRecord() throws Exception {
        PublicationsFile mockedTrustProvider = Mockito.mock(PublicationsFile.class);
        KSISignature signature = TestUtil.loadSignature("calendar-auth-rec-missing.ksig");

        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, mockedExtenderClient, TestUtil.getFileHash(loadFile("infile"), "SHA2-256"), mockedTrustProvider), new KeyBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_2);
        Map<Rule, RuleResult> resultMap = result.getPolicyVerificationResults().get(0).getRuleResults();
        RuleResult[] ruleResults = resultMap.values().toArray(new RuleResult[resultMap.size()]);
        Assert.assertEquals(ruleResults[ruleResults.length - 1].getResultCode(), VerificationResultCode.NA);
        Assert.assertEquals(ruleResults[ruleResults.length - 1].getRuleName(), CalendarAuthenticationRecordExistenceRule.class.getSimpleName());
    }

    @Test
    public void testVerifySignatureOfflineSignedByUnknownCertificate() throws Exception {
        PublicationsFile mockedTrustProvider = Mockito.mock(PublicationsFile.class);
        Mockito.when(mockedTrustProvider.findCertificateById(Mockito.any(byte[].class))).thenThrow(new CertificateNotFoundException("Certificate not found"));
        Mockito.when(mockedTrustProvider.getName()).thenReturn("MockProvider");
        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-04-30.1.ksig");
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, mockedExtenderClient, TestUtil.getFileHash(loadFile("infile"), "SHA2-256"), mockedTrustProvider), new KeyBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.KEY_01);
    }

    @Test
    public void testVerifySignatureOfflineUsingInvalidPublicKey() throws Exception {
        PublicationsFile mockedTrustProvider = Mockito.mock(PublicationsFile.class);
        X509Certificate mockedCertificate = Mockito.mock(X509Certificate.class);
        Mockito.when(mockedCertificate.getSigAlgName()).thenReturn("RSA");
        Mockito.when(mockedTrustProvider.findCertificateById(Mockito.any(byte[].class))).thenReturn(mockedCertificate);
        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-04-30.1.ksig");
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, mockedExtenderClient, TestUtil.getFileHash(loadFile("infile"), "SHA2-256"), mockedTrustProvider), new KeyBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.KEY_02);
    }

    @Test
    public void testVerifySignatureOfflineUsingInvalidAlgorithm() throws Exception {
        PublicationsFile mockedTrustProvider = Mockito.mock(PublicationsFile.class);
        X509Certificate mockedCertificate = Mockito.mock(X509Certificate.class);
        Mockito.when(mockedCertificate.getSigAlgName()).thenReturn("BLABLA_ALG");
        Mockito.when(mockedTrustProvider.findCertificateById(Mockito.any(byte[].class))).thenReturn(mockedCertificate);
        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-04-30.1.ksig");
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, mockedExtenderClient, TestUtil.getFileHash(loadFile("infile"), "SHA2-256"), mockedTrustProvider), new KeyBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.KEY_02);
    }


}
