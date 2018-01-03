/*
 * Copyright 2013-2016 Guardtime, Inc.
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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.integration.AbstractCommonIntegrationTest;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH;
import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH_2;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class KsiBlockSignerIntegrationTest extends AbstractCommonIntegrationTest {

    private static final String WORKING_HASH_ALGORITHMS = "workingHashAlgorithms";

    private IdentityMetadata metadata;
    private IdentityMetadata metadata2;
    private IdentityMetadata metadata3;
    private IdentityMetadata metadata4;
    private DataHash dataHashSha1;
    private DataHash dataHashSha386;
    private DataHash dataHashSha512;
    private DataHash dataHashRipemd160;

    @Override
    @BeforeClass
    public void setUp() throws Exception {
        super.setUp();
        metadata = new IdentityMetadata("test1");
        metadata2 = new IdentityMetadata("test2", "machine-id-1", 1L, System.currentTimeMillis());
        metadata3 = new IdentityMetadata("test3");
        metadata4 = new IdentityMetadata("test4");
        this.dataHashSha1 = new DataHash(HashAlgorithm.SHA1, new byte[20]);
        this.dataHashSha386 = new DataHash(HashAlgorithm.SHA2_384, new byte[48]);
        this.dataHashSha512 = new DataHash(HashAlgorithm.SHA2_512, new byte[64]);
        this.dataHashRipemd160 = new DataHash(HashAlgorithm.RIPEMD_160, new byte[20]);
    }

    @DataProvider(name = WORKING_HASH_ALGORITHMS)
    public Object[][] hashAlgorithms() {
        List<Object[]> hashAlgorithms = new ArrayList<>();
        Date currentDate = new Date();
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            if (HashAlgorithm.Status.NOT_IMPLEMENTED != algorithm.getStatus() && !algorithm.isDeprecated(currentDate)) {
                hashAlgorithms.add(new Object[]{algorithm});
            }
        }
        Object[][] objects = new Object[hashAlgorithms.size()][];
        return hashAlgorithms.toArray(objects);
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*The request indicated client-side aggregation tree larger than allowed for the client.*")
    public void testCreateSignatureLargeAggregationTree() throws Exception {
        KsiBlockSigner builder = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        builder.add(DATA_HASH, 254L, metadata);
        builder.sign();
    }

    @Test
    public void testBlockSignerUsingDefaultHashingAlgorithm() throws Exception {
        KsiBlockSigner builder = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        builder.add(DATA_HASH, metadata);
        builder.add(DATA_HASH_2, metadata2);
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
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).setDefaultHashAlgorithm(algorithm).build();
        blockSigner.add(dataHashSha512, metadata4);
        blockSigner.add(dataHashRipemd160, metadata2);
        blockSigner.add(dataHashSha386, metadata3);

        signAndVerify(blockSigner, 3);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Hash algorithm SHA1 is marked deprecated since .*")
    public void testBlockSignerWithDeprecatedHashAlgorithms() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        blockSigner.add(dataHashSha1, metadata);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Hash algorithm SHA1 is marked deprecated since .*")
    public void testInitBlockSignerWithDeprecatedHashAlgorithm() throws Exception {
        new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).setDefaultHashAlgorithm(HashAlgorithm.SHA1).build();
    }

    @Test
    public void testBlockSignerWithMaxTreeHeightAndPerformVerification() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).setMaxTreeHeight(3).build();
        // Up to 4 hashes with meta data could be added without exceeding max tree height 3.
        assertTrue(blockSigner.add(DATA_HASH, metadata));
        assertTrue(blockSigner.add(DATA_HASH, metadata));
        assertTrue(blockSigner.add(DATA_HASH, metadata));
        assertTrue(blockSigner.add(DATA_HASH, metadata));
        assertFalse(blockSigner.add(DATA_HASH, metadata));

        signAndVerify(blockSigner, 4);
    }

    @Test
    public void testBlockSignerWithVerification() throws Exception {
        PublicationsFileClientAdapter mockAdapter = Mockito.mock(PublicationsFileClientAdapter.class);
        when(mockAdapter.getPublicationsFile()).thenReturn(ksi.getPublicationsFile());
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder()
                .setKsiSigningClient(simpleHttpClient)
                .setMaxTreeHeight(3)
                .setSignatureFactory(new InMemoryKsiSignatureFactory(
                        new KeyBasedVerificationPolicy(),
                        mockAdapter,
                        simpleHttpClient,
                        false,
                        new InMemoryKsiSignatureComponentFactory()
                )).build();

        assertTrue(blockSigner.add(DATA_HASH, metadata));
        assertTrue(blockSigner.add(DATA_HASH, metadata));
        assertTrue(blockSigner.add(DATA_HASH, metadata));
        assertTrue(blockSigner.add(DATA_HASH, metadata));
        assertFalse(blockSigner.add(DATA_HASH, metadata));

        signAndVerify(blockSigner, 4);

    }

    @Test
    public void testBlockSignerWithVerificationLevelDesc() throws Exception {
        PublicationsFileClientAdapter mockAdapter = Mockito.mock(PublicationsFileClientAdapter.class);
        when(mockAdapter.getPublicationsFile()).thenReturn(ksi.getPublicationsFile());
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder()
                .setKsiSigningClient(simpleHttpClient)
                .setMaxTreeHeight(4)
                .setSignatureFactory(new InMemoryKsiSignatureFactory(
                        new KeyBasedVerificationPolicy(),
                        mockAdapter,
                        simpleHttpClient,
                        false,
                        new InMemoryKsiSignatureComponentFactory()
                        )).build();

        assertTrue(blockSigner.add(DATA_HASH, 2L, metadata));
        assertTrue(blockSigner.add(DATA_HASH, 1L, metadata));
        assertTrue(blockSigner.add(DATA_HASH, metadata));

        signAndVerify(blockSigner, 3);
    }

    @Test
    public void testBlockSignerWithVerificationLevelRandomOrder() throws Exception {
        PublicationsFileClientAdapter mockAdapter = Mockito.mock(PublicationsFileClientAdapter.class);
        when(mockAdapter.getPublicationsFile()).thenReturn(ksi.getPublicationsFile());
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder()
                .setKsiSigningClient(simpleHttpClient)
                .setMaxTreeHeight(5)
                .setSignatureFactory(new InMemoryKsiSignatureFactory(
                        new KeyBasedVerificationPolicy(),
                        mockAdapter,
                        simpleHttpClient,
                        false,
                        new InMemoryKsiSignatureComponentFactory()
                        )).build();

        assertTrue(blockSigner.add(DATA_HASH, 1L, metadata));
        assertTrue(blockSigner.add(DATA_HASH, metadata));
        assertTrue(blockSigner.add(DATA_HASH, 2L, metadata));

        signAndVerify(blockSigner, 3);
    }

    @Test
    public void testBlockSignerSignatureOutputOrder() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        List<Input> input = Arrays.asList(
                new Input(DATA_HASH, 3L, metadata),
                new Input(DATA_HASH, 0L, metadata3),
                new Input(DATA_HASH_2, 0L, metadata2),
                new Input(dataHashSha386, 3L, metadata),
                new Input(DATA_HASH, 0L, metadata4),
                new Input(DATA_HASH, 0L, metadata),
                new Input(DATA_HASH, 2L, metadata3),
                new Input(DATA_HASH_2, 1L, metadata),
                new Input(DATA_HASH_2, 1L, metadata2),
                new Input(dataHashSha386, 0L, metadata4),
                new Input(dataHashSha386, 1L, metadata3));
        Collections.shuffle(input);

        addDataAndSignAndVerify(blockSigner, input);
    }

    @Test
    public void testBlockSignerWithoutMetadata() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        blockSigner.add(DATA_HASH);
        blockSigner.add(DATA_HASH);
        blockSigner.add(DATA_HASH);
        signAndVerify(blockSigner, 3);
    }

    @Test
    public void testBlockSignerOneHashWithoutMetadata() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        blockSigner.add(DATA_HASH);
        signAndVerify(blockSigner, 1);
    }

    @Test
    public void testBlockSignerWithoutMetadataLevel() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        List<Input> hashes = Arrays.asList(
                new Input(DATA_HASH, 2L, null),
                new Input(DATA_HASH, 3L, null),
                new Input(DATA_HASH, 2L, null),
                new Input(DATA_HASH, 3L, null),
                new Input(DATA_HASH, 1L, null));

        addDataAndSignAndVerify(blockSigner, hashes);
    }

    @Test
    public void testBlockSignerOneHashLevelWithoutMetadata() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        List<Input> hashes = Collections.singletonList(new Input(DATA_HASH, 2L, null));

        addDataAndSignAndVerify(blockSigner, hashes);
    }

    @Test
    public void testBlockSignerWithJustOneHash() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        List<Input> hashes = Collections.singletonList(new Input(DATA_HASH, 0L, null));

        addDataAndSignAndVerify(blockSigner, hashes);
    }

    private void addDataAndSignAndVerify(KsiBlockSigner blockSigner, List<Input> hashes) throws Exception {
        for (Input input : hashes) {
            blockSigner.add(input.getDataHash(), input.getLevel(), input.getMetadata());
        }

        signAndVerifyWithLevel(blockSigner, hashes);
    }

    private void signAndVerifyWithLevel(KsiBlockSigner signer, List<Input> input) throws Exception {
        List<KSISignature> signatures = signer.sign();
        assertNotNull(signatures);
        assertFalse(signatures.isEmpty());
        assertEquals(signatures.size(), input.size());
        int i = 0;

        ContextAwarePolicy policy = ContextAwarePolicyAdapter.createKeyPolicy(getPublicationsHandler(simpleHttpClient));
        for (KSISignature signature : signatures) {
            VerificationResult verificationResult =
                    ksi.verify(signature, input.get(i).getDataHash(), input.get(i).getLevel(), policy);
            assertTrue(verificationResult.isOk());
            if (input.get(i).getMetadata() != null) {
                assertEquals(signature.getAggregationHashChainIdentity()[signature.getAggregationHashChainIdentity().length - 1].getDecodedClientId(),
                        input.get(i).getMetadata().getClientId());
            }
            i++;
        }
    }

    private void signAndVerify(KsiBlockSigner signer, int size) throws KSIException {
        List<KSISignature> signatures = signer.sign();
        assertNotNull(signatures);
        assertFalse(signatures.isEmpty());
        assertEquals(signatures.size(), size);
        for (KSISignature signature : signatures) {
            assertTrue(ksi.verify(signature, new KeyBasedVerificationPolicy()).isOk());
        }
    }

    private static class Input {
        private DataHash dataHash;
        private Long level;
        private IdentityMetadata metadata;

        public Input(DataHash dataHash, Long level, IdentityMetadata metadata) {
            super();
            this.dataHash = dataHash;
            this.level = level;
            this.metadata = metadata;
        }

        public DataHash getDataHash() {
            return dataHash;
        }

        public Long getLevel() {
            return level;
        }

        public IdentityMetadata getMetadata() {
            return metadata;
        }
    }

}
