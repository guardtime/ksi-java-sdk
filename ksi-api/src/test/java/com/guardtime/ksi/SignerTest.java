/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

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
            expectedExceptionsMessageRegExp = "Hash algorithm SHA1 is marked deprecated since .*")
    public void testSignerBuilderWithDeprecatedAlgorithm() throws KSIException {
        new SignerBuilder().setSigningService(mockedSigningService).setDefaultSigningHashAlgorithm(HashAlgorithm.SHA1).build();
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Hash algorithm SHA1 is marked deprecated since .*")
    public void testSignWithDeprecatedAlgorithm() throws KSIException {
        Signer signer = new SignerBuilder().setSigningService(mockedSigningService).build();
        signer.sign(new DataHash(HashAlgorithm.SHA1, new byte[20]));
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Hash algorithm SHA1 is marked deprecated since .*")
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
