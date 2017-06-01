package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class ExtenderBuilderTest {

    private X509CertificateSubjectRdnSelector certSelector;
    private KSIExtenderClient mockedExtenderClient;
    private KSISigningClient mockedSigningClient;
    private KSIPublicationsFileClient mockedPublicationsFileClient;

    @BeforeClass
    public void setUp() throws Exception {
        this.certSelector = new X509CertificateSubjectRdnSelector("E=publications@guardtime.com");
        mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);
        mockedSigningClient = Mockito.mock(KSISigningClient.class);
        mockedPublicationsFileClient = Mockito.mock(KSIPublicationsFileClient.class);
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI extender client can not be null")
    public void testExtenderBuilderWithoutExtenderClient() throws KSIException {
        new ExtenderBuilder().build();
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI publications file can not be null")
    public void testExtenderBuilderWithoutPublicationsFileClient() throws KSIException {
        new ExtenderBuilder()
                .setExtenderClient(mockedExtenderClient)
                .build();
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI publications file trusted certificate selector can not be null")
    public void testExtenderBuilderWithoutCertSelector() throws KSIException {
        new ExtenderBuilder()
                .setExtenderClient(mockedExtenderClient)
                .setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient)
                .build();
    }

    @Test
    public void testExtenderBuilderOk() throws KSIException {
        Extender extender = new ExtenderBuilder()
                .setExtenderClient(mockedExtenderClient)
                .setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient)
                .setPublicationsFileCertificateConstraints(certSelector)
                .build();
        Assert.assertNotNull(extender);
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI signing client can not be null")
    public void testSignerBuilderWithoutSigningClient() throws KSIException {
        new SignerBuilder().build();
    }

    @Test
    public void testSignerBuilderOk() throws KSIException {
        Signer signer = new SignerBuilder().setSignerClient(mockedSigningClient).build();
        Assert.assertNotNull(signer);
    }

}
