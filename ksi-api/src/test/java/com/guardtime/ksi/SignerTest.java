package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.KSISigningService;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class SignerTest {
    private KSISigningService mockedSigningService;

    @BeforeClass
    public void setUp() throws Exception {
        mockedSigningService = Mockito.mock(KSISigningService.class);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Hash algorithm SHA1 is marked deprecated")
    public void testSignerBuilderWithDeprecatedAlgorithm() throws KSIException {
        new SignerBuilder().setSigningService(mockedSigningService).setDefaultSigningHashAlgorithm(HashAlgorithm.SHA1).build();
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Hash algorithm SHA1 is marked deprecated")
    public void testSignWithDeprecatedAlgorithm() throws KSIException {
        Signer signer = new SignerBuilder().setSigningService(mockedSigningService).build();
        signer.sign(new DataHash(HashAlgorithm.SHA1, new byte[20]));
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Hash algorithm SHA1 is marked deprecated")
    public void testAsyncSignWithDeprecatedAlgorithm() throws KSIException {
        Signer signer = new SignerBuilder().setSigningService(mockedSigningService).build();
        signer.asyncSign(new DataHash(HashAlgorithm.SHA1, new byte[20]));
    }
}
