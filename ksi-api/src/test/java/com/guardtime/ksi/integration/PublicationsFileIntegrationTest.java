package com.guardtime.ksi.integration;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.trust.CryptoException;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;

import org.bouncycastle.util.Store;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_CERT;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_HEADER;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD2;
import static com.guardtime.ksi.Resources.SIGNATURE_2014_06_02;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;

public class PublicationsFileIntegrationTest extends AbstractCommonIntegrationTest {

    private final PublicationsFileBasedVerificationPolicy policy = new PublicationsFileBasedVerificationPolicy();

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationRecordLvl1() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD, true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationRecordLvl2() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD2, true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInCertificateRecord() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_CERT, true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationHeader() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_HEADER, true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    private VerificationResult publicationFileBasedVerification(String signatureFile, String publicationFile, boolean extendingAllowed, KSIExtenderClient extenderClient) throws Exception {
        VerificationContextBuilder build = new VerificationContextBuilder();
        build.setPublicationsFile(new InMemoryPublicationsFileFactory(new PKITrustStore() {
            public boolean isTrusted(X509Certificate certificate, Store certStore) throws CryptoException {
                return true;
            }
        }).create(load(publicationFile)));
        KSISignature signature = TestUtil.loadSignature(signatureFile);
        build.setSignature(signature).setExtenderClient(extenderClient);
        build.setExtendingAllowed(extendingAllowed);
        return ksi.verify(build.createVerificationContext(), policy);
    }
}
