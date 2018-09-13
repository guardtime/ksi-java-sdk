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
import java.util.LinkedHashMap;
import java.util.Map;

import static com.guardtime.ksi.Resources.SIGNATURE_WITH_LEVEL_CORRECTION_1;
import static com.guardtime.ksi.Resources.SIGNATURE_WITH_LEVEL_CORRECTION_3;
import static com.guardtime.ksi.Resources.SIGNATURE_WITH_LEVEL_CORRECTION_5;
import static java.util.Collections.singletonMap;
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
        new AggregationHashChainBuilder().build(node1.getParent());
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Aggregation hash chain can be built only from leaf nodes")
    public void testCreateAggregationHashChainFromRootNode_throwsIllegalArgumentException() throws KSIException {
        ImprintNode node = new ImprintNode(new DataHash(Base16.decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
        new AggregationHashChainBuilder().build(node);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Aggregation hash chain can be built only from leaf nodes")
    public void testCreateAggregationHashChainFromMetadataNode_throwsIllegalArgumentException() throws KSIException {
        MetadataNode node = new MetadataNode(new byte[]{1}, 0);
        new AggregationHashChainBuilder().build(node);
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
        Map<ImprintNode, IdentityMetadata> nodes = new LinkedHashMap<>();

        nodes.put(new ImprintNode(new DataHash(Base16.decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")), 0L), null);
        nodes.put(new ImprintNode(new DataHash(Base16.decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")), 0L), null);
        nodes.put(new ImprintNode(new DataHash(Base16.decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")), 1L), null);
        nodes.put(new ImprintNode(new DataHash(Base16.decode("01680192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")), 1L), null);
        nodes.put(new ImprintNode(new DataHash(Base16.decode("019D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")), 1L), null);

        buildTreeAndExtractAggregationChainsAndVerify(signature, nodes);
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
        Map<ImprintNode, IdentityMetadata> input = new LinkedHashMap<>();

        input.put(
                new ImprintNode(
                        new DataHash(Base16.decode("04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                        0L
                ),
                new IdentityMetadata("test3")
        );

        input.put(
                new ImprintNode(
                        new DataHash(Base16.decode("020000000000000000000000000000000000000000")),
                        1L
                ),
                new IdentityMetadata("test2", "machine-id-1", 1L, 1517236554764L)
        );

        input.put(
                new ImprintNode(
                        new DataHash(Base16.decode("0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                        4L
                ),
                null
        );

        buildTreeAndExtractAggregationChainsAndVerify(signature, input);
    }

    @Test
    public void testCreateAggregationHashChainWithHeight1FromTreeLeafWithMetadata_Ok() throws Exception {
        /*
               01E4EE0B 1
               /‾‾‾‾‾‾‾‾‾‾\
          01000000       test1
         */
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_WITH_LEVEL_CORRECTION_1);
        ImprintNode node = new ImprintNode(
                new DataHash(Base16.decode("010000000000000000000000000000000000000000000000000000000000000000")),
                0L
        );
        buildTreeAndExtractAggregationChainsAndVerify(signature, singletonMap(node, new IdentityMetadata("test1")));
    }

    private void buildTreeAndExtractAggregationChainsAndVerify(KSISignature signature, Map<ImprintNode, IdentityMetadata> nodes) throws Exception {
        HashAlgorithm aggregationAlgorithm = signature.getInputHash().getAlgorithm();
        HashTreeBuilder treeBuilder = new HashTreeBuilder(aggregationAlgorithm);
        for (ImprintNode node : nodes.keySet()) {
            IdentityMetadata metadata = nodes.get(node);
            if (metadata == null) {
                treeBuilder.add(node);
            } else {
                treeBuilder.add(node, metadata);
            }
        }

        for (ImprintNode node : nodes.keySet()) {
            DataHash inputHash = new DataHash(node.getValue());
            AggregationHashChainBuilder chainBuilder = new AggregationHashChainBuilder();
            AggregationHashChain chain = chainBuilder.build(node);
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
}