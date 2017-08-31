package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSISigningService;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class ExtenderBuilderTest {

    private KSIExtendingService mockedExtendingService;
    private KSISigningService mockedSigningService;
    private PublicationsHandler mockedPublicationsHandler;

    @BeforeClass
    public void setUp() throws Exception {
        mockedExtendingService = Mockito.mock(KSIExtendingService.class);
        mockedSigningService = Mockito.mock(KSISigningService.class);
        mockedPublicationsHandler = Mockito.mock(PublicationsHandler.class);
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI extending service can not be null")
    public void testExtenderBuilderWithoutExtendingService() throws KSIException {
        new ExtenderBuilder().build();
    }

    @Test(expectedExceptions = {NullPointerException.class}, expectedExceptionsMessageRegExp = "KSI publications handler can not be null")
    public void testExtenderBuilderWithoutPublicationsHandler() throws KSIException {
        new ExtenderBuilder()
                .setExtendingService(mockedExtendingService)
                .build();
    }

    @Test
    public void testExtenderBuilderOk() throws KSIException {
        Extender extender = new ExtenderBuilder()
                .setExtendingService(mockedExtendingService)
                .setPublicationsHandler(mockedPublicationsHandler)
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
