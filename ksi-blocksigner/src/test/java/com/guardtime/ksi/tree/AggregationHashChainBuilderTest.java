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

package com.guardtime.ksi.tree;

import com.guardtime.ksi.SignatureVerifier;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.blocksigner.IdentityMetadata;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.util.Base16;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;

import static com.guardtime.ksi.Resources.SIGNATURE_WITH_LEVEL_CORRECTION_3;
import static com.guardtime.ksi.Resources.SIGNATURE_WITH_LEVEL_CORRECTION_5;
import static org.testng.Assert.assertEquals;

public class AggregationHashChainBuilderTest {

    private ContextAwarePolicy policy = ContextAwarePolicyAdapter.createInternalPolicy();
    private InMemoryKsiSignatureFactory signatureFactory;
    private SignatureVerifier verifier = new SignatureVerifier();

    @BeforeClass
    public void setUp() {
        this.signatureFactory = new InMemoryKsiSignatureFactory(policy, new InMemoryKsiSignatureComponentFactory());
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Aggregation hash chain can be built only from leaf nodes")
    public void testCreateAggregationHashChainFromNonLeafNode_throwsIllegalArgumentException() throws KSIException {
        HashTreeBuilder treeBuilder = new HashTreeBuilder(HashAlgorithm.SHA2_256);
        ImprintNode node1 = new ImprintNode(new DataHash(Base16.decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
        ImprintNode node2 = new ImprintNode(new DataHash(Base16.decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")));
        treeBuilder.add(node1, node2);
        new AggregationHashChainBuilder(node1.getParent(), new Date()).build();
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Aggregation hash chain can be built only from leaf nodes")
    public void testCreateAggregationHashChainFromRootNode_throwsIllegalArgumentException() throws KSIException {
        HashTreeBuilder treeBuilder = new HashTreeBuilder(HashAlgorithm.SHA2_256);
        ImprintNode node = new ImprintNode(new DataHash(Base16.decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
        treeBuilder.add(node);
        new AggregationHashChainBuilder(node, new Date()).build();
    }

    @Test
    public void testCreateAggregationHashChainFromTreeLeafWithoutMetadata_Ok() throws Exception {

        /*                                 5A848EE
                             / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                          5950DCA                           D4F6E36
                    / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                        / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                 C9AF37D              \                  /              \
                 /    \                \                /                \
            580192B  8D982C6        14F9189          680192B           9D982C6
        */


        KSISignature signature = TestUtil.loadSignature(SIGNATURE_WITH_LEVEL_CORRECTION_3);
        Map<ImprintNode, MetadataInput> input = new LinkedHashMap<>();

        input.put(new ImprintNode(new DataHash(Base16.decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")), 0L), null);
        input.put(new ImprintNode(new DataHash(Base16.decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")), 0L), null);
        input.put(new ImprintNode(new DataHash(Base16.decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")), 1L), null);
        input.put(new ImprintNode(new DataHash(Base16.decode("01680192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")), 1L), null);
        input.put(new ImprintNode(new DataHash(Base16.decode("019D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")), 1L), null);

        buildTreeAndExtractAggregationChainsAndVerify(signature, input);
    }

    @Test
    public void testCreateAggregationHashChainFromTreeLeafWithMetadata_Ok() throws Exception {
       /*                               5A848EE
                                 /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
                           014024AA 1                 \
                    /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\                 \
                 0178BAFB 1            01979985          \
               /‾‾‾‾‾‾‾‾‾‾\             /‾‾‾‾‾‾‾‾‾‾‾‾\           \
          04000000       test3   02000000 1   test2    05000000 4
        */

        KSISignature signature = TestUtil.loadSignature(SIGNATURE_WITH_LEVEL_CORRECTION_5);
        Map<ImprintNode, MetadataInput> input = new LinkedHashMap<>();

        ImprintNode node1 = new ImprintNode(new DataHash(Base16.decode("0178BAFB1F3AF73B661F9C7B4ADC30DE5A7B715184A4543B200694101C1A8C0E02")), 1L);
        MetadataInput metadataInput1 = new MetadataInput(
                new IdentityMetadata("test3"),
                new DataHash(Base16.decode("04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")));
        input.put(node1, metadataInput1);

        ImprintNode node2 = new ImprintNode(new DataHash(Base16.decode("01979985EED807EC9E036D679D327B7BEFF0CA0D127524B0AD6EC37414EBE96258")), 2L);
        MetadataInput metadataInput2 = new MetadataInput(
                new IdentityMetadata("test2", "machine-id-1", 1L, 1517236554764L),
                new DataHash(Base16.decode("020000000000000000000000000000000000000000")));
        input.put(node2, metadataInput2);

        ImprintNode node3 = new ImprintNode(new DataHash(Base16.decode("0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")), 4L);
        input.put(node3, null);

        buildTreeAndExtractAggregationChainsAndVerify(signature, input);
    }

    private void buildTreeAndExtractAggregationChainsAndVerify(KSISignature signature, Map<ImprintNode, MetadataInput> data) throws Exception {
        HashAlgorithm aggregationAlgorithm = signature.getInputHash().getAlgorithm();
        HashTreeBuilder treeBuilder = new HashTreeBuilder(aggregationAlgorithm);
        for (ImprintNode node : data.keySet()) {
            treeBuilder.add(node);
        }

        for (ImprintNode node : data.keySet()) {
            DataHash inputHash = new DataHash(node.getValue());
            AggregationHashChainBuilder chainBuilder = new AggregationHashChainBuilder(node, signature.getAggregationTime())
                    .setAggregationAlgorithm(aggregationAlgorithm)
                    .setChainIndex(new LinkedList<>(signature.getAggregationHashChains()[0].getChainIndex()));
            MetadataInput metadataInput = data.get(node);
            if (metadataInput != null) {
                chainBuilder.setMetadata(metadataInput.getMetadata(), metadataInput.getInputHash());
                inputHash = metadataInput.getInputHash();
            }
            AggregationHashChain chain = chainBuilder.build();
            createSignatureWithAggregationChainAndVerify(chain, signature, inputHash);
        }
    }

    private void createSignatureWithAggregationChainAndVerify(AggregationHashChain chain, KSISignature signature, DataHash inputHash) throws Exception {
        ByteArrayOutputStream signatureBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream signatureBytesAfterSignatureCreation = new ByteArrayOutputStream();
        signature.writeTo(signatureBytes);

        KSISignature newSignature = signatureFactory.createSignature(signature, chain, inputHash);
        signature.writeTo(signatureBytesAfterSignatureCreation);

        assertEquals(signatureBytesAfterSignatureCreation.toByteArray(), signatureBytes.toByteArray());
        VerificationResult result = verifier.verify(newSignature, inputHash, this.policy);
        Assert.assertTrue(result.isOk());
    }

    private class MetadataInput {
        private IdentityMetadata metadata;
        private DataHash inputHash;

        MetadataInput(IdentityMetadata metadata, DataHash inputHash) {
            this.metadata = metadata;
            this.inputHash = inputHash;
        }

        IdentityMetadata getMetadata() {
            return metadata;
        }

        DataHash getInputHash() {
            return inputHash;
        }
    }
}