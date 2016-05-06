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
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.*;

public class KsiBlockSignerIntegrationTest extends AbstractBlockSignatureTest {

    private KsiSignatureMetadata metadata = new KsiSignatureMetadata("test1");

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*The request indicated client-side aggregation tree larger than allowed for the client")
    public void testCreateSignatureLargeAggregationTree() throws Exception {
        KsiBlockSigner builder = new KsiBlockSigner(simpleHttpClient);
        builder.add(dataHash, 255L, metadata);
        builder.sign();
    }

    @Test
    public void testBlockSigner() throws Exception {
        KsiBlockSigner builder = new KsiBlockSigner(simpleHttpClient);
        builder.add(dataHash, metadata);
        builder.add(dataHash2, metadata);
        builder.add(dataHash3, metadata);

        List<KSISignature> signatures = builder.sign();
        assertNotNull(signatures);
        assertFalse(signatures.isEmpty());
        assertEquals(signatures.size(), 3L);
        for (KSISignature signature : signatures) {
            assertTrue(ksi.verify(signature, new KeyBasedVerificationPolicy()).isOk());
        }
    }

}
