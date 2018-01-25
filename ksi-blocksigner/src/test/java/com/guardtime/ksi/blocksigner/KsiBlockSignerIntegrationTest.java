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

package com.guardtime.ksi.blocksigner;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.integration.AbstractCommonIntegrationTest;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.util.Base16;

import org.mockito.Mockito;
import org.testng.Assert;
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
import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH_3;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_LEGACY_ID;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_LEGADY_ID_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_METADATA;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_METADATA_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH_AND_LEVEL;
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
    private DataHash dataHash;
    private DataHash dataHashSha1;
    private DataHash dataHashSha386;
    private DataHash dataHashSha512;
    private DataHash dataHashRipemd160;
    private ServiceCredentials credentials;

    @Override
    @BeforeClass
    public void setUp() throws Exception {
        super.setUp();
        this.metadata = new IdentityMetadata("test1");
        this.metadata2 = new IdentityMetadata("test2", "machine-id-1", 1L, System.currentTimeMillis());
        this.metadata3 = new IdentityMetadata("test3");
        this.metadata4 = new IdentityMetadata("test4");
        this.dataHash = new DataHash(Base16.decode("0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d"));
        this.dataHashSha1 = new DataHash(HashAlgorithm.SHA1, new byte[20]);
        this.dataHashSha386 = new DataHash(HashAlgorithm.SHA2_384, new byte[48]);
        this.dataHashSha512 = new DataHash(HashAlgorithm.SHA2_512, new byte[64]);
        this.dataHashRipemd160 = new DataHash(HashAlgorithm.RIPEMD_160, new byte[20]);
        this.credentials = loadHTTPSettings().getCredentials();
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

    @Test(dataProvider = WORKING_HASH_ALGORITHMS)
    public void testBlockSignerWithAllWorkingHashAlgorithms(HashAlgorithm algorithm) throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).setDefaultHashAlgorithm(algorithm).build();
        List<Input> input = Arrays.asList(
                new Input(dataHashSha512, 1L, metadata4),
                new Input(dataHashRipemd160, 2L, metadata2),
                new Input(DATA_HASH, 3L, metadata),
                new Input(dataHashSha386, 0L, metadata3));

        addDataAndSignAndVerify(blockSigner, input);
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
    public void testBlockSignerSignatureOutputOrder() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        List<Input> input = Arrays.asList(
                new Input(DATA_HASH, 3L, metadata),
                new Input(dataHash, 0L, metadata3),
                new Input(DATA_HASH_2, 0L, metadata2),
                new Input(dataHashSha386, 3L, metadata),
                new Input(DATA_HASH, 0L, metadata4),
                new Input(dataHashSha512, 0L, metadata),
                new Input(DATA_HASH, 2L, metadata3),
                new Input(DATA_HASH_2, 1L, metadata),
                new Input(DATA_HASH_3, 1L, metadata2),
                new Input(dataHashSha386, 0L, metadata4),
                new Input(dataHashRipemd160, 1L, metadata3));
        Collections.shuffle(input);

        addDataAndSignAndVerify(blockSigner, input);
    }

    @Test
    public void testBlockSignerWithoutMetadata() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        List<Input> input = Arrays.asList(
                new Input(DATA_HASH, 2L, null),
                new Input(dataHashSha386, 0L, null),
                new Input(DATA_HASH_2, 1L, null),
                new Input(dataHashSha386, 3L, null));
        Collections.shuffle(input);

        addDataAndSignAndVerify(blockSigner, input);
    }

    @Test
    public void testBlockSignerWithoutMetadataAndLevel() throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningClient(simpleHttpClient).build();
        List<Input> hashes = Arrays.asList(
                new Input(DATA_HASH, 0L, null),
                new Input(dataHashSha386, 0L, null),
                new Input(dataHash, 0L, null),
                new Input(dataHashSha512, 0L, null),
                new Input(dataHashRipemd160, 0L, null));

        addDataAndSignAndVerify(blockSigner, hashes);
    }

    @Test
    public void testRequestWithHashResponseHasFirstRightLinkWithMetadata() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA, 0, 0, false, 4);
    }

    @Test
    public void testRequestWithHashResponseHasFirstRightLinkWithSiblingHash() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH, 0, 0, false, 2);
    }

    @Test
    public void testRequestWithHashResponseHasFirstRightLinkWithLegacyId() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID, 0, 0, false, 3);
    }

    @Test
    public void testRequestWithHashAndLevelResponseHasFirstRightLinkWithMetadata() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA_AND_LEVEL, 2, 5, false, 4);
    }

    @Test
    public void testRequestWithHashAndLevelResponseHasFirstRightLinkWithSiblingHash() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH_AND_LEVEL, 2, 5, false, 2);
    }

    @Test
    public void testRequestWithHashAndLevelResponseHasFirstRightLinkWithLegacyId() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID_AND_LEVEL, 2, 5, false, 3);
    }

    @Test
    public void testRequestWithHashResponseHasFirstLeftLinkWithMetadata() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_METADATA, 0, 0, true, 4);
    }

    @Test
    public void testRequestWithHashResponseHasFirstLeftLinkWithSiblingHash() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH, 0, 0, true, 2);
    }

    @Test
    public void testRequestWithHashResponseHasFirstLeftLinkWithLegacyId() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_LEGACY_ID, 0, 0, true, 3);
    }

    @Test
    public void testRequestWithHashAndLevelResponseHasFirstLeftLinkWithMetadata() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_METADATA_AND_LEVEL, 2, 5, true, 4);
    }

    @Test
    public void testRequestWithHashAndLevelResponseHasFirstLeftLinkWithSiblingHash() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH_AND_LEVEL, 2, 5, true, 2);
    }

    @Test
    public void testRequestWithHashAndLevelResponseHasFirstLeftLinkWithLegacyId() throws Exception {
        checkResponses(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_LEGADY_ID_AND_LEVEL, 2, 5, true, 3);

    }

    private void checkResponses(String response, long requestLevel, long levelCorrection, boolean firstLinkIsLeft, int expectedSiblingType) throws Exception {
        KsiBlockSigner blockSigner = new KsiBlockSignerBuilder().setKsiSigningService(mockSigningService(response, credentials)).build();
        Input input = new Input(dataHash, requestLevel, null);
        blockSigner.add(input.getDataHash(), input.getLevel(), input.getMetadata());
        List<KSISignature> signatures = blockSigner.sign();
        Assert.assertEquals(signatures.size(), 1);
        long level = signatures.get(0).getAggregationHashChains()[0].getChainLinks().get(0).getLevelCorrection();
        Assert.assertTrue(level == (requestLevel + levelCorrection),
                "Expected link level " + (requestLevel + levelCorrection) + " but found " + level);

        Assert.assertEquals(signatures.get(0).getAggregationHashChains()[0].getChainLinks().get(0).isLeft(), firstLinkIsLeft,
                "Expected link direction was not found.");

        Assert.assertNotNull(((TLVStructure)signatures.get(0).getAggregationHashChains()[0].getChainLinks().get(0)).getRootElement().getFirstChildElement(expectedSiblingType),
                "Expected sibling data type of " + expectedSiblingType + " was not found.");
    }

    private void addDataAndSignAndVerify(KsiBlockSigner blockSigner, List<Input> inputList) throws Exception {
        for (Input input : inputList) {
            blockSigner.add(input.getDataHash(), input.getLevel(), input.getMetadata());
        }
        List<KSISignature> signatures = blockSigner.sign();
        assertNotNull(signatures);
        assertFalse(signatures.isEmpty());
        assertEquals(signatures.size(), inputList.size());
        int i = 0;

        ContextAwarePolicy policy = ContextAwarePolicyAdapter.createKeyPolicy(getPublicationsHandler(simpleHttpClient));
        for (KSISignature signature : signatures) {
            VerificationResult verificationResult =
                    ksi.verify(signature, inputList.get(i).getDataHash(), inputList.get(i).getLevel(), policy);
            assertTrue(verificationResult.isOk());
            if (inputList.get(i).getMetadata() != null) {
                assertEquals(signature.getAggregationHashChainIdentity()[signature.getAggregationHashChainIdentity().length - 1].getDecodedClientId(),
                        inputList.get(i).getMetadata().getClientId());
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
