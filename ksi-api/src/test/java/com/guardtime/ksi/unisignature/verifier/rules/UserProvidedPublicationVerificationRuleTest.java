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

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Date;

public class UserProvidedPublicationVerificationRuleTest extends AbstractRuleTest {

    private UserProvidedPublicationVerificationRule rule = new UserProvidedPublicationVerificationRule();

    @Test
    public void testUserPublicationDoesNotEqualToSignaturePublication_Ok() throws Exception {
        PublicationData publication = new PublicationData(new Date(), new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        RuleResult result = rule.verify(build(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig"), publication));
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.NA);
    }

    @Test
    public void testUserPublicationEqualToSignaturePublication_Ok() throws Exception {
        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig");
        Assert.assertEquals(rule.verify(build(signature, signature.getPublicationRecord().getPublicationData())).getResultCode(), VerificationResultCode.OK);
    }

}