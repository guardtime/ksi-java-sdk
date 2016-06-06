package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.testng.Assert;
import org.testng.annotations.Test;

public class AggregationHashChainLinkMetadataRuleTest extends AbstractRuleTest {

    private static final String SIGNATURE_WITH_METADATA_MATCHING_HASH_IMPRINT = "aggregation-hash-chain-metadata/metadata-content-matches-hash-imprint.ksig";
    private static final String SIGNATURE_WITH_MISSING_METADATA_PADDING = "aggregation-hash-chain-metadata/metadata-missing-padding-element.ksig";
    private static final String SIGNATURE_WITH_MULTIPLE_METADATA_PADDINGS = "aggregation-hash-chain-metadata/metadata-multiple-padding-elements.ksig";
    private static final String SIGNATURE_WITH_METADATA_PADDING_FLAGS_NOT_SET = "aggregation-hash-chain-metadata/metadata-padding-flags-not-set.ksig";
    private static final String SIGNATURE_WITH_METADATA_PADDING_F_FLAG_NOT_SET = "aggregation-hash-chain-metadata/metadata-padding-forward-flag-not-set.ksig";
    private static final String SIGNATURE_WITH_METADATA_PADDING_N_FLAG_NOT_SET = "aggregation-hash-chain-metadata/metadata-padding-noncritical-flag-not-set.ksig";
    private static final String SIGNATURE_WITH_METADATA_PADDING_TLV_16_FLAG_SET = "aggregation-hash-chain-metadata/metadata-padding-16-bit-flag-set.ksig";
    private static final String SIGNATURE_WITH_METADATA_PADDING_TOO_LONG = "aggregation-hash-chain-metadata/metadata-padding-too-long.ksig";
    private static final String SIGNATURE_WITH_METADATA_PADDING_TOO_SHORT = "aggregation-hash-chain-metadata/metadata-padding-too-short.ksig";
    private static final String SIGNATURE_WITH_BAD_METADATA_PADDING = "aggregation-hash-chain-metadata/metadata-padding-wrong-content.ksig";
    private static final String SIGNATURE_WITH_WRONG_METADATA_ORDER = "aggregation-hash-chain-metadata/metadata-wrong-order.ksig";
    private static final String SIGNATURE_WITH_VALID_METADATA = "aggregation-hash-chain-metadata/metadata-signed-ok.ksig";
    private AggregationHashChainLinkMetadataRule rule = new AggregationHashChainLinkMetadataRule();

    @Test
    public void testCorrectMetadataWithPadding() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_VALID_METADATA)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithMissingPaddingNotMistakenForHashImprint() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_MISSING_METADATA_PADDING)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingNotFirstElement() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_WRONG_METADATA_ORDER)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithMultiplePadding() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_MULTIPLE_METADATA_PADDINGS)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithTooLongPadding() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_METADATA_PADDING_TOO_LONG)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithInvalidPaddingContent() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_BAD_METADATA_PADDING)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingForwardFlagNotSet() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_METADATA_PADDING_F_FLAG_NOT_SET)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingNonCriticalFlagNotSet() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_METADATA_PADDING_N_FLAG_NOT_SET)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingTLV16FlagSet() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_METADATA_PADDING_TLV_16_FLAG_SET)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingNoFlagsSet() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_METADATA_PADDING_FLAGS_NOT_SET)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataWithPaddingTooShort() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_METADATA_PADDING_TOO_SHORT)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testMetadataMatchesHashImprint() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_METADATA_MATCHING_HASH_IMPRINT)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_11);
    }


}