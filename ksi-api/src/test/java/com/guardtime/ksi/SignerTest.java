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

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Level must be between 0 and 255")
    public void testSignWithNegativeLevel() throws KSIException {
        Signer signer = new SignerBuilder().setSigningService(mockedSigningService).build();
        signer.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]), -2);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Level must be between 0 and 255")
    public void testSignWithLargeLevel() throws KSIException {
        Signer signer = new SignerBuilder().setSigningService(mockedSigningService).build();
        signer.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]), 300);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Level must be between 0 and 255")
    public void testAsyncSignWithNegativeLevel() throws KSIException {
        Signer signer = new SignerBuilder().setSigningService(mockedSigningService).build();
        signer.asyncSign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]), -2);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Level must be between 0 and 255")
    public void testAsyncSignWithLargeLevel() throws KSIException {
        Signer signer = new SignerBuilder().setSigningService(mockedSigningService).build();
        signer.asyncSign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]), 300);
    }

}
