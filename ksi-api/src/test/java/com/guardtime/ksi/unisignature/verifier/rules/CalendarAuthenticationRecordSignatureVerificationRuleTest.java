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

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.util.Base16;
import com.guardtime.ksi.util.X509CertUtil;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE;
import static com.guardtime.ksi.Resources.SIGNATURE_2014_06_02;

public class CalendarAuthenticationRecordSignatureVerificationRuleTest {

    private CalendarAuthenticationRecordSignatureVerificationRule rule = new CalendarAuthenticationRecordSignatureVerificationRule();
    private VerificationContext context;

    @BeforeMethod
    public void setUp() throws Exception {
        this.context = Mockito.mock(VerificationContext.class);
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2014_06_02);
        Mockito.when(context.getSignature()).thenReturn(signature);
        Mockito.when(context.getCalendarAuthenticationRecord()).thenReturn(signature.getCalendarAuthenticationRecord());
        Mockito.when(context.getCalendarHashChain()).thenReturn(signature.getCalendarHashChain());
    }

    @Test
    public void testSignatureWithCorrectCalendarAuthenticationRecordReturnsOkStatus_Ok() throws Exception {
        PublicationsFile pubFile = TestUtil.loadPublicationsFile(PUBLICATIONS_FILE);
        Mockito.when(context.getCertificate(Mockito.any(byte[].class))).thenReturn(pubFile.findCertificateById(Base16.decode("C246B139")));
        Assert.assertEquals(rule.verify(context).getResultCode(), VerificationResultCode.OK);
    }

    @Test
    public void testSignatureVerificationUsesUnknownAlgorithmReturnsFailedStatus_Ok() throws Exception {
        X509Certificate mockCertificate = Mockito.mock(X509Certificate.class);
        Mockito.when(mockCertificate.getSigAlgName()).thenReturn("INVALID_ALG");
        Mockito.when(context.getCertificate(Mockito.any(byte[].class))).thenReturn(mockCertificate);
        RuleResult result = rule.verify(context);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.KEY_02);
    }

    @Test
    public void testSignatureContainsInvalidPKISignatureThenReturnsFailedStatus_Ok() throws Exception {
        Mockito.when(context.getCertificate(Mockito.any(byte[].class))).thenReturn(X509CertUtil.toCert(TestUtil.loadBytes("cert.crt")));
        Assert.assertEquals(rule.verify(context).getResultCode(), VerificationResultCode.FAIL);
    }

}