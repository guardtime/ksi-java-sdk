package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.testng.Assert;
import org.testng.annotations.Test;

public class Rfc3161RecordTimeRuleTest  extends AbstractRuleTest {

    private Rfc3161RecordTimeRule rule = new Rfc3161RecordTimeRule();

    @Test
    public void testSignatureRfc3161RecordContainsInvalidTime() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_RFC3161_RECORD_INVALID_AGGREGATION_TIME)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(rule.getErrorCode(), VerificationErrorCode.INT_02);
    }

    @Test
    public void testSignatureRfc3161RecordTimeIsValid() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_WITH_RFC3161_RECORD)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

}
