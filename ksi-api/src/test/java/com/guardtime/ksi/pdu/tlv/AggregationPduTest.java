package com.guardtime.ksi.pdu.tlv;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.integration.AbstractCommonIntegrationTest;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;

import org.testng.annotations.Test;

public class AggregationPduTest {

    private static final ServiceCredentials CREDENTIALS = TestUtil.CREDENTIALS_ANONYMOUS;

    @Test
    public void testCreateAggregationPdu_Ok() throws Exception {
//        PduHeader header = new PduHeader(CREDENTIALS.getLoginId(), 1L, 1L);
//        TLVElement payload = new TLVElement(false, false, 0x0201);
//        payload.addChildElement(TLVElement.create(0x01, 42L));
//        payload.addChildElement(TLVElement.create(0x02, new DataHash(HashAlgorithm.SHA2_256, new byte[32])));
//
//        AggregationRequestPdu aggregationPdu = new AggregationRequestPdu(header, Arrays.asList(payload), HashAlgorithm.SHA2_256, CREDENTIALS.getLoginKey());
//        assertNotNull(aggregationPdu);
//
//        AggregationRequestPdu parsedPdu = new AggregationRequestPdu(aggregationPdu.getRootElement(), CREDENTIALS.getLoginKey());
//
//        byte[] bytes = aggregationPdu.getRootElement().getEncoded();

        SimpleHttpClient client = new SimpleHttpClient(AbstractCommonIntegrationTest.loadHTTPSettings());
        X509CertificateSubjectRdnSelector certSelector = new X509CertificateSubjectRdnSelector("E=publications@guardtime.com");
        KSI ksi = new KSIBuilder().
                setKsiProtocolSignerClient(client).
                setKsiProtocolExtenderClient(client).
                setKsiProtocolPublicationsFileClient(client).
                setDefaultSigningHashAlgorithm(HashAlgorithm.SHA2_256).
                setPublicationsFileTrustedCertSelector(certSelector).
                setPduFactory(new TlvKsiPduFactory()).
                build();

        verify(ksi, ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32])), new KeyBasedVerificationPolicy());
        verify(ksi, ksi.extend(TestUtil.loadSignature("ok-sig-2014-06-2.ksig")), new PublicationsFileBasedVerificationPolicy());

    }

    private void verify(KSI ksi, KSISignature signature, Policy policy) throws KSIException {
        VerificationResult result = ksi.verify(signature, policy);
        if (!result.isOk()) {
            System.err.println("Panic");
        }
    }


}
