package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class ExtenderBuilderTest {

    private X509CertificateSubjectRdnSelector certSelector;
    private KSIExtendingService mockedExtendingService;
    private KSISigningService mockedSigningService;
    private KSIPublicationsFileClient mockedPublicationsFileClient;

    @BeforeClass
    public void setUp() throws Exception {
        this.certSelector = new X509CertificateSubjectRdnSelector("E=publications@guardtime.com");
        mockedExtendingService = Mockito.mock(KSIExtendingService.class);
        mockedSigningService = Mockito.mock(KSISigningService.class);
        mockedPublicationsFileClient = Mockito.mock(KSIPublicationsFileClient.class);
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI extending service can not be null")
    public void testExtenderBuilderWithoutExtendingService() throws KSIException {
        new ExtenderBuilder().build();
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI publications file can not be null")
    public void testExtenderBuilderWithoutPublicationsFileClient() throws KSIException {
        new ExtenderBuilder()
                .setExtendingService(mockedExtendingService)
                .build();
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI publications file trusted certificate selector can not be null")
    public void testExtenderBuilderWithoutCertSelector() throws KSIException {
        new ExtenderBuilder()
                .setExtendingService(mockedExtendingService)
                .setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient)
                .build();
    }

    @Test
    public void testExtenderBuilderOk() throws KSIException {
        Extender extender = new ExtenderBuilder()
                .setExtendingService(mockedExtendingService)
                .setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient)
                .setPublicationsFileCertificateConstraints(certSelector)
                .build();
        Assert.assertNotNull(extender);
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI signing service can not be null")
    public void testSignerBuilderWithoutSigningService() throws KSIException {
        new SignerBuilder().build();
    }

    @Test
    public void testSignerBuilderOk() throws KSIException {
        Signer signer = new SignerBuilder().setSigningService(mockedSigningService).build();
        Assert.assertNotNull(signer);
    }

}
