package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.testng.Assert;
import org.testng.annotations.Test;

public class Rfc3161RecordIndexRuleTest extends AbstractRuleTest {

    private Rfc3161RecordIndexRule rule = new Rfc3161RecordIndexRule();

    @Test
    public void testSignatureContainsInvalidRfc3161Index() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_RFC3161_RECORD_INVALID_CHAIN_INDEX)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_10);
    }

    @Test
    public void testSignatureContainsValidRfc3161Index() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_RFC3161_RECORD)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

}
