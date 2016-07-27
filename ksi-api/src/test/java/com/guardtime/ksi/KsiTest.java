package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.pdu.exceptions.InvalidMessageAuthenticationCodeException;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.util.Util;
import org.bouncycastle.util.Store;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.TestUtil.loadSignature;
import static com.guardtime.ksi.TestUtil.PUBLICATIONS_FILE_27_07_2016;

public class KsiTest {

    private X509CertificateSubjectRdnSelector certSelector;

    private KSISigningClient mockedSigningClient;
    private KSIExtenderClient mockedExtenderClient;
    private KSIPublicationsFileClient mockedPublicationsFileClient;
    private PKITrustStore mockedTrustStore;
    private Future mockedResponse;
    private Future mockedPublicationsFileResponse;

    private PduIdentifierProvider mockedIdentifierProvider;

    private KSI ksi;
    private DataHash defaultDataHash;

    @BeforeMethod
    public void setUp() throws Exception {
        this.certSelector = new X509CertificateSubjectRdnSelector("E=publications@guardtime.com");
        mockedSigningClient = Mockito.mock(KSISigningClient.class);
        mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);
        mockedPublicationsFileClient = Mockito.mock(KSIPublicationsFileClient.class);
        mockedTrustStore = Mockito.mock(PKITrustStore.class);
        mockedIdentifierProvider = Mockito.mock(PduIdentifierProvider.class);

        Mockito.when(mockedIdentifierProvider.getInstanceId()).thenReturn(42L);
        Mockito.when(mockedIdentifierProvider.nextMessageId()).thenReturn(42L);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(42275443333883166L);
        Mockito.when(mockedSigningClient.getServiceCredentials()).thenReturn(TestUtil.CREDENTIALS_ANONYMOUS);
        Mockito.when(mockedExtenderClient.getServiceCredentials()).thenReturn(TestUtil.CREDENTIALS_ANONYMOUS);

        Mockito.when(mockedTrustStore.isTrusted(Mockito.any(X509Certificate.class), Mockito.any(Store.class))).thenReturn(true);
        mockedResponse = Mockito.mock(Future.class);

        mockedPublicationsFileResponse = Mockito.mock(Future.class);
        Mockito.when(mockedPublicationsFileResponse.getResult()).thenReturn(ByteBuffer.wrap(Util.toByteArray(load(PUBLICATIONS_FILE_27_07_2016))));
        Mockito.when(mockedPublicationsFileClient.getPublicationsFile()).thenReturn(mockedPublicationsFileResponse);

        this.defaultDataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(TestUtil.load("ksi-truststore.jks"), "changeit".toCharArray());

        this.ksi = new KSIBuilder().
                setKsiProtocolExtenderClient(mockedExtenderClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient).
                setPublicationsFileTrustedCertSelector(certSelector).
                setKsiProtocolSignerClient(mockedSigningClient).
                setPublicationsFilePkiTrustStore(keyStore).
                setPduIdentifierProvider(mockedIdentifierProvider).build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI signing client must be present")
    public void testCreateKsiInstanceWithoutSigningClient_ThrowsKsiException() throws Exception {
        new KSIBuilder().
                setKsiProtocolExtenderClient(mockedExtenderClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient).
                setPublicationsFileTrustedCertSelector(certSelector).build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI publications file client must be present")
    public void testCreateKsiInstanceWithoutPublicationsFileClient_ThrowsKsiException() throws Exception {
        new KSIBuilder().
                setKsiProtocolSignerClient(mockedSigningClient).
                setKsiProtocolExtenderClient(mockedExtenderClient).
                setPublicationsFileTrustedCertSelector(certSelector).build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI extender client must be present")
    public void testCreateKsiInstanceWithoutExtenderClient_ThrowsKsiException() throws Exception {
        new KSIBuilder().
                setKsiProtocolSignerClient(mockedSigningClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient).
                setPublicationsFileTrustedCertSelector(certSelector).build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI publications file trusted certificate selector must be present")
    public void testCreateKsiInstanceWithoutPublicationsFileTrustedCertSelector_ThrowsKsiException() throws Exception {
        new KSIBuilder().
                setKsiProtocolSignerClient(mockedSigningClient).
                setKsiProtocolExtenderClient(mockedExtenderClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient).build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "File not-present-signature.ksig not found")
    public void testReadUniSignatureUsingFileNotPresent_ThrowsKSIException() throws Exception {
        ksi.read(new File("not-present-signature.ksig"));
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. File can not be null")
    public void testReadUniSignatureUsingInvalidFileInput_ThrowsKSIException() throws Exception {
        ksi.read((File) null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Byte array can not be null")
    public void testReadUniSignatureUsingInvalidByteArrayInput_ThrowsKSIException() throws Exception {
        ksi.read((byte[]) null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Input stream can not be null")
    public void testReadUniSignatureUsingInvalidInputStream_ThrowsKSIException() throws Exception {
        ksi.read((InputStream) null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Data hash must not be null")
    public void testSignMissingDataHash_ThrowsKSIException() throws Exception {
        ksi.sign((DataHash) null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. File must not be null")
    public void testSignMissingFile_ThrowsKSIException() throws Exception {
        ksi.sign((File) null);
    }


    // sign

    @Test
    public void testCreateSignature_Ok() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-response.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);

        KSISignature response = ksi.sign(defaultDataHash);
        Assert.assertNotNull(response);
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = InvalidMessageAuthenticationCodeException.class, expectedExceptionsMessageRegExp = "Invalid MAC code. Expected.*")
    public void testResponseContainsInvalidMac_ThrowsInvalidMessageAuthenticationCodeException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-response-invalid-mac.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        ksi.sign(defaultDataHash);
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*request IDs do not match, sent .* received .*")
    public void testResponseContainsInvalidRequestId_ThrowsKSIProtocolException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-response.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(42275443333883167L);
        ksi.sign(defaultDataHash);
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Response message does not contain response payload element")
    public void testResponseDoesNotContainResponseTlvTag_ThrowsKSIProtocolException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-response-missing-response-tag.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        ksi.sign(defaultDataHash);
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(5\\):Response error 5: Invalid request format")
    public void testResponseContains203ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-203-error.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        ksi.sign(defaultDataHash);
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(769\\):Server error")
    public void testResponseContainsErrorMessageInside202TLVMessage_ThrowsKSIProtocolException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-202-error.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        ksi.sign(defaultDataHash);
    }

    @Test
    public void testNormalOperations_Ok() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension-response-sig-2014-04-30.1.ksig"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(5546551786909961666L);

        KSISignature result = ksi.extend(loadSignature("ok-sig-2014-04-30.1.ksig"));
        Assert.assertNotNull(result);
        Assert.assertTrue(result.isExtended());
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Can't parse response message")
    public void testResponseFormatException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-invalid.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(5546551786909961666L);

        ksi.extend(loadSignature("ok-sig-2014-04-30.1.ksig"));
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = InvalidMessageAuthenticationCodeException.class, expectedExceptionsMessageRegExp = "Invalid MAC code. Expected.*")
    public void testResponseInvalidHMAC_ThrowsInvalidMessageAuthenticationCodeException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-invalid-hmac.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(5546551786909961666L);

        ksi.extend(loadSignature("ok-sig-2014-04-30.1.ksig"));
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*request IDs do not match, sent \\'[0-9]+\\' received \\'4321\\'")
    public void testRequestIdsMismatch() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-ok-request-id-4321.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(5546551786909961666L);

        ksi.extend(loadSignature("ok-sig-2014-04-30.1.ksig"));
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Response message does not contain response payload element")
    public void testRequestResponseEmpty() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-missing-response-payload.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(5546551786909961666L);

        ksi.extend(loadSignature("ok-sig-2014-04-30.1.ksig"));
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(404\\):Not found")
    public void testRequest404ErrorWithResponse() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-with-error-payload.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(4321L);

        ksi.extend(loadSignature("ok-sig-2014-04-30.1.ksig"));
    }

    // TODO move to Legacy tests?
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(404\\):Response error 404: Not found")
    public void testResponseWithError() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-error-response-with-header.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(5546551786909961666L);

        ksi.extend(loadSignature("ok-sig-2014-04-30.1.ksig"));
    }

    @Test
    public void testGetPublicationsFile_Ok() throws Exception {
        PublicationsFile response = ksi.getPublicationsFile();
        Assert.assertNotNull(response);
        Assert.assertEquals(response, TestUtil.loadPublicationsFile(PUBLICATIONS_FILE_27_07_2016));
    }

}
