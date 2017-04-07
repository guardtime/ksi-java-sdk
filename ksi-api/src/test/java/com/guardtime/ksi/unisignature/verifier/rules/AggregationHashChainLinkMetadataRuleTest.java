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
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_MATCHING_HASH_IMPRINT;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_MISSING_PADDING;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_MULTIPLE_PADDINGS;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_PADDING_FLAGS_NOT_SET;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_PADDING_F_FLAG_NOT_SET;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_PADDING_N_FLAG_NOT_SET;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_PADDING_TLV_16_FLAG_SET;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_PADDING_TOO_LONG;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_PADDING_TOO_SHORT;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_WRONG_CONTENT;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_WRONG_ORDER;

public class AggregationHashChainLinkMetadataRuleTest extends AbstractRuleTest {

    private AggregationHashChainLinkMetadataRule rule = new AggregationHashChainLinkMetadataRule();

    @Test
    public void testCorrectMetadataWithPadding() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_2017_03_14)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithMissingPaddingNotMistakenForHashImprint() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_MISSING_PADDING)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingNotFirstElement() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_WRONG_ORDER)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithMultiplePadding() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_MULTIPLE_PADDINGS)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithTooLongPadding() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_PADDING_TOO_LONG)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithInvalidPaddingContent() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_WRONG_CONTENT)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingForwardFlagNotSet() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_PADDING_F_FLAG_NOT_SET)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingNonCriticalFlagNotSet() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_PADDING_N_FLAG_NOT_SET)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingTLV16FlagSet() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_PADDING_TLV_16_FLAG_SET)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingNoFlagsSet() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_PADDING_FLAGS_NOT_SET)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingTooShort() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_PADDING_TOO_SHORT)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataMatchesHashImprint() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_METADATA_MATCHING_HASH_IMPRINT)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }


}
