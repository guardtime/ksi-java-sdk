package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Date;

public class UserProvidedPublicationHashEqualsToSignaturePublicationHashRuleTest extends AbstractRuleTest {

    private Rule rule = new UserProvidedPublicationHashEqualsToSignaturePublicationHashRule();

    @Test
    public void testUserPublicationHashDoesNotEqualToSignaturePublicationHash_Ok() throws Exception {
        PublicationData publication = new PublicationData(new Date(), new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        RuleResult result = rule.verify(build(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig"), publication));
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.PUB_04);
    }

    @Test
    public void testUserPublicationHashEqualToSignaturePublicationHash_Ok() throws Exception {
        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig");
        Assert.assertEquals(rule.verify(build(signature, signature.getPublicationRecord().getPublicationData())).getResultCode(), VerificationResultCode.OK);
    }

}
