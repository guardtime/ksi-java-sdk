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
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.security.cert.Certificate;

import static com.guardtime.ksi.Resources.SIGNATURE_2014_06_02;

public class CertificateExistenceRuleTest {

    private CertificateExistenceRule rule = new CertificateExistenceRule();
    private VerificationContext context;

    @BeforeMethod
    public void setUp() throws Exception {
        this.context = Mockito.mock(VerificationContext.class);
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2014_06_02);
        Mockito.when(context.getSignature()).thenReturn(signature);
        Mockito.when(context.getCalendarAuthenticationRecord()).thenReturn(signature.getCalendarAuthenticationRecord());
        Mockito.when(context.getCertificate(Mockito.any(byte[].class))).thenReturn(null);
    }

    @Test
    public void testWhenCertificateNotPresentThenRuleReturnsFailedStatus_Ok() throws Exception {
        Mockito.when(context.getCertificate(Mockito.any(byte[].class))).thenReturn(null);
        RuleResult result = rule.verify(context);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.KEY_01);
    }

    @Test
    public void testWhenCertificateIsPresentThenRuleReturnsOkStatus_Ok() throws Exception {
        Certificate mockedCertificate = Mockito.mock(Certificate.class);
        Mockito.when(context.getCertificate(Mockito.any(byte[].class))).thenReturn(mockedCertificate);
        RuleResult result = rule.verify(context);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

}