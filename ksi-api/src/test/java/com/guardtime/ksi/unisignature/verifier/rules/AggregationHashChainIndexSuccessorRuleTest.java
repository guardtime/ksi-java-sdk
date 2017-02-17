package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.testng.Assert;
import org.testng.annotations.Test;

public class AggregationHashChainIndexSuccessorRuleTest extends AbstractRuleTest {

    private AggregationHashChainIndexSuccessorRule rule = new AggregationHashChainIndexSuccessorRule();

    @Test
    public void testSignatureWithInvalidAggregationChainIndexValue() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature("signature/signature-with-invalid-aggregation-chain-index-value.ksig")));
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_12);
    }

    @Test
    public void testSignatureWithMissingOneAggregationChain() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature("signature/signature-with-missing-one-aggregation-chain.ksig")));
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_12);
    }

    @Test
    public void testValidSignature_Ok() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature("ok-sig-2014-06-2.ksig")));
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
        Assert.assertNull(result.getErrorCode());
    }

}
