package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.SignaturePublicationRecord;
import com.guardtime.ksi.unisignature.verifier.policies.InternalVerificationPolicy;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static java.util.Arrays.asList;

public class InMemoryKsiSignatureFactoryTest {

    private static final String PUBLICATIONS_FILE_15042014 = "publications.15042014.tlv";
    private static final String TEST_SIGNATURE = "ok-sig-2014-06-2.ksig";
    private static final String PUBLICATION_STRING = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
    private InMemoryKsiSignatureComponentFactory signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
    private InMemoryKsiSignatureFactory signatureFactory;
    private PublicationsFileClientAdapter mockedPublicationsFileAdapter;

    @BeforeMethod
    public void setUp() throws Exception {
        this.mockedPublicationsFileAdapter = Mockito.mock(PublicationsFileClientAdapter.class);
        Mockito.when(mockedPublicationsFileAdapter.getPublicationsFile()).thenReturn(TestUtil.loadPublicationsFile(PUBLICATIONS_FILE_15042014));
        this.signatureFactory = new InMemoryKsiSignatureFactory(new InternalVerificationPolicy(),
                mockedPublicationsFileAdapter, Mockito.mock(KSIExtenderClient.class), false,
                new InMemoryKsiSignatureComponentFactory());
    }

    @Test
    public void testCreateValidKsiSignature_Ok() throws Exception {
        KSISignature signature = signatureFactory.createSignature(TestUtil.loadTlv(TEST_SIGNATURE), null);
        Assert.assertNotNull(signature);
    }

    @Test(expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = "Signature .* is invalid: GEN_1.*Wrong document.*")
    public void testCreateSignatureWithInvalidInputHash_ThrowsInvalidSignatureContentException() throws Exception {
        signatureFactory.createSignature(TestUtil.loadTlv(TEST_SIGNATURE), new DataHash(HashAlgorithm.SHA1, new byte[20]));
    }

    @Test(expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = "Signature .* is invalid: INT_09.*")
    public void testCreateSignatureFromInvalidComponents_ThrowsInvalidSignatureContentException() throws Exception {
        KSISignature signature = TestUtil.loadSignature(TEST_SIGNATURE);
        SignaturePublicationRecord publicationRecord = signatureComponentFactory.createPublicationRecord(new PublicationData(PUBLICATION_STRING), null, null);
        signatureFactory.createSignature(asList(signature.getAggregationHashChains()), signature.getCalendarHashChain(), signature.getCalendarAuthenticationRecord(), publicationRecord, null);
    }

}
