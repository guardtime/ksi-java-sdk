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
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Date;

import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2014_06_02;
import static com.guardtime.ksi.Resources.SIGNATURE_2014_04_30;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE;

public class PublicationsFileContainsPublicationRuleTest extends AbstractRuleTest {

    private PublicationsFileContainsPublicationRule rule = new PublicationsFileContainsPublicationRule();

    private VerificationContext context;

    @BeforeMethod
    public void setUp() throws Exception {
        this.context = Mockito.mock(VerificationContext.class);
        Mockito.when(context.getPublicationsFile()).thenReturn(TestUtil.loadPublicationsFile(PUBLICATIONS_FILE));
    }

    @Test
    public void testPublicationFileContainsPublication_Ok() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(EXTENDED_SIGNATURE_2014_06_02), TestUtil.loadPublicationsFile(PUBLICATIONS_FILE)));
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

    //TODO: Start using new resource pack files.
    @Test
    public void testSignatureDoesNotContainPublicationRecordButSuitableInPublicationsFile_Ok() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_2014_04_30), TestUtil.loadPublicationsFile(PUBLICATIONS_FILE)));
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

    @Test
    public void testPublicationFileDoesNotContainPublication_NA() throws Exception {
        CalendarHashChain mockedChain = Mockito.mock(CalendarHashChain.class);
        Mockito.when(mockedChain.getRegistrationTime()).thenReturn(new Date());
        Mockito.when(context.getCalendarHashChain()).thenReturn(mockedChain);
        Assert.assertEquals(rule.verify(context).getResultCode(), VerificationResultCode.NA);
    }

}