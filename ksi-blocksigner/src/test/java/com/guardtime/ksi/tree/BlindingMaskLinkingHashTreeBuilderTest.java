/*
 * Copyright 2013-2019 Guardtime, Inc.
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

import com.guardtime.ksi.AbstractBlockSignatureTest;
import com.guardtime.ksi.blocksigner.IdentityMetadata;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.util.Util;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH;
import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH_2;
import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH_3;

public class BlindingMaskLinkingHashTreeBuilderTest {

    public static final byte[] INITIALIZATION_VECTOR = new byte[32];
    private final DataHasher hasher = new DataHasher(HashAlgorithm.SHA2_256);

    @Test
    public void testBlindingMasksCalculation() {
        BlindingMaskLinkingHashTreeBuilder treeBuilder = new BlindingMaskLinkingHashTreeBuilder(INITIALIZATION_VECTOR, DATA_HASH);
        treeBuilder.add(
                new ImprintNode(AbstractBlockSignatureTest.DATA_HASH_2),
                new ImprintNode(AbstractBlockSignatureTest.DATA_HASH_3)
        );

        ImprintNode root = treeBuilder.build();
        Assert.assertEquals(root.getLevel(), 2);

        DataHash firstSignatureMask = hasher.addData(DATA_HASH).addData(INITIALIZATION_VECTOR).getHash();

        // Test first blinding mask
        TreeNode blindingMask1 = root.getLeftChildNode().getLeftChildNode();
        Assert.assertEquals(new DataHash(blindingMask1.getValue()), firstSignatureMask);

        hasher.reset();

        // Test first node value
        DataHash nodeDataHash = hasher.addData(firstSignatureMask).addData(AbstractBlockSignatureTest.DATA_HASH_2).addData(Util.encodeUnsignedLong(1)).getHash();
        Assert.assertEquals(new DataHash(root.getLeftChildNode().getValue()), nodeDataHash);

        hasher.reset();

        // Test second blinding mask
        DataHash secondMask = hasher.addData(nodeDataHash).addData(INITIALIZATION_VECTOR).getHash();
        TreeNode blindingMask2 = root.getRightChildNode().getLeftChildNode();
        Assert.assertEquals(new DataHash(blindingMask2.getValue()), secondMask);

        hasher.reset();

        // Test second node value
        nodeDataHash = hasher.addData(secondMask).addData(AbstractBlockSignatureTest.DATA_HASH_3).addData(Util.encodeUnsignedLong(1)).getHash();
        Assert.assertEquals(new DataHash(root.getRightChildNode().getValue()), nodeDataHash);

        // Test tree builder output hash
        Assert.assertEquals(new DataHash(root.getRightChildNode().getValue()), treeBuilder.getLastNodeHash());
    }

    @Test
    public void testCalculateHeight() {
        BlindingMaskLinkingHashTreeBuilder builder = createTreeBuilder();
        builder.add(new ImprintNode(DATA_HASH_2));
        Assert.assertEquals(builder.calculateHeight(new ImprintNode(DATA_HASH_3)), 2);
    }

    @Test(expectedExceptions = UnsupportedOperationException.class, expectedExceptionsMessageRegExp = "Identity metadata is not supported by BlindingMaskLinkingHashTreeBuilder")
    public void testCalculateHeightThrowsExceptionWhenIdentityMetadataIsPresent() {
        BlindingMaskLinkingHashTreeBuilder builder = createTreeBuilder();
        builder.calculateHeight(new ImprintNode(DATA_HASH_2), new IdentityMetadata("1"));
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "HashAlgorithm can not be null")
    public void testCreateTreeBuilderUsingNullHashAlgorithm() {
        new BlindingMaskLinkingHashTreeBuilder(null,INITIALIZATION_VECTOR, AbstractBlockSignatureTest.DATA_HASH_2);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Initialization vector can not be null")
    public void testCreateTreeBuilderUsingNullInitializationVector() {
        new BlindingMaskLinkingHashTreeBuilder(HashAlgorithm.SHA2_256,null, AbstractBlockSignatureTest.DATA_HASH_2);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Initialization vector should be as long as the output of the hash algorithm")
    public void testCreateTreeBuilderUsingInitializationVectorWithInvalidLength() {
        new BlindingMaskLinkingHashTreeBuilder(HashAlgorithm.SHA2_256,new byte[16], AbstractBlockSignatureTest.DATA_HASH_2);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Node can not be null")
    public void testAddNullNodeToHashBuilder() {
        BlindingMaskLinkingHashTreeBuilder builder = createTreeBuilder();
        builder.add((ImprintNode) null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "ImprintNode with level greater than 0 is not supported by BlindingMaskLinkingHashTreeBuilder")
    public void testAddNodeWithLevelTwoToHashBuilder() {
        BlindingMaskLinkingHashTreeBuilder builder = createTreeBuilder();
        builder.add(new ImprintNode(DATA_HASH_2, 2));
    }

    @Test(expectedExceptions = UnsupportedOperationException.class, expectedExceptionsMessageRegExp = "Identity metadata is not supported by BlindingMaskLinkingHashTreeBuilder")
    public void testAddNodeWithMetadataToHashBuilder() {
        BlindingMaskLinkingHashTreeBuilder builder = createTreeBuilder();
        builder.add(new ImprintNode(DATA_HASH_2), new IdentityMetadata("ClientId"));
    }

    private BlindingMaskLinkingHashTreeBuilder createTreeBuilder() {
        return new BlindingMaskLinkingHashTreeBuilder(INITIALIZATION_VECTOR);
    }

}