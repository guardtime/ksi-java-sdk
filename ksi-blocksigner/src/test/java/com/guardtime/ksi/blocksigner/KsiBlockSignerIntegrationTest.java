/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

package com.guardtime.ksi.blocksigner;

import com.guardtime.ksi.AbstractBlockSignatureTest;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.*;

public class KsiBlockSignerIntegrationTest extends AbstractBlockSignatureTest {

    private static final String WORKING_HASH_ALGORITHMS = "workingHashAlgorithms";

    private KsiSignatureMetadata metadata = new KsiSignatureMetadata("test1");
    private KsiSignatureMetadata metadata2 = new KsiSignatureMetadata("test2");
    private KsiSignatureMetadata metadata3 = new KsiSignatureMetadata("test3");
    private KsiSignatureMetadata metadata4 = new KsiSignatureMetadata("test4");
    private DataHash dataHashSha1;
    private DataHash dataHashSha386;
    private DataHash dataHashSha512;
    private DataHash dataHashRipemd160;

    @Override
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        this.dataHashSha1 = new DataHash(HashAlgorithm.SHA1, new byte[20]);
        this.dataHashSha386 = new DataHash(HashAlgorithm.SHA2_384, new byte[48]);
        this.dataHashSha512 = new DataHash(HashAlgorithm.SHA2_512, new byte[64]);
        this.dataHashRipemd160 = new DataHash(HashAlgorithm.RIPEMD_160, new byte[20]);
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*The request indicated client-side aggregation tree larger than allowed for the client")
    public void testCreateSignatureLargeAggregationTree() throws Exception {
        KsiBlockSigner builder = new KsiBlockSigner(simpleHttpClient);
        builder.add(dataHash, 255L, metadata);
        builder.sign();
    }

    @Test
    public void testBlockSignerUsingDefaultHashingAlgorithm() throws Exception {
        KsiBlockSigner builder = new KsiBlockSigner(simpleHttpClient);
        builder.add(dataHash, metadata);
        builder.add(dataHash2, metadata2);
        builder.add(dataHashSha386, metadata3);

        List<KSISignature> signatures = builder.sign();
        assertNotNull(signatures);
        assertFalse(signatures.isEmpty());
        assertEquals(signatures.size(), 3L);
        for (KSISignature signature : signatures) {
            assertTrue(ksi.verify(signature, new KeyBasedVerificationPolicy()).isOk());
            assertEquals(signature.getAggregationHashChains()[0].getAggregationAlgorithm(), HashAlgorithm.SHA2_256);
        }
    }

    @Test(dataProvider = WORKING_HASH_ALGORITHMS)
    public void testBlockSignerWithAllWorkingHashAlgorithms(HashAlgorithm algorithm) throws Exception {
        KsiBlockSigner builder = new KsiBlockSigner(simpleHttpClient, algorithm);
        builder.add(dataHashSha512, metadata4);
        builder.add(dataHashSha1, metadata);
        builder.add(dataHashRipemd160, metadata2);
        builder.add(dataHashSha386, metadata3);

        List<KSISignature> signatures = builder.sign();
        assertNotNull(signatures);
        assertFalse(signatures.isEmpty());
        assertEquals(signatures.size(), 4L);
        for (KSISignature signature : signatures) {
            assertTrue(ksi.verify(signature, new KeyBasedVerificationPolicy()).isOk());
        }
    }

    @DataProvider(name = WORKING_HASH_ALGORITHMS)
    public Object[][] hashAlgorithms() {
        List<Object[]> hashAlgorithms = new ArrayList<Object[]>();
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            if (HashAlgorithm.Status.NOT_IMPLEMENTED != algorithm.getStatus()) {
                hashAlgorithms.add(new Object[]{algorithm});
            }
        }
        Object[][] objects = new Object[hashAlgorithms.size()][];
        return hashAlgorithms.toArray(objects);
    }

}
