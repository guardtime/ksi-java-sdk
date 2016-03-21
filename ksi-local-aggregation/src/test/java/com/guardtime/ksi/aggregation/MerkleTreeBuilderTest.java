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

package com.guardtime.ksi.aggregation;

import static org.testng.Assert.*;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class MerkleTreeBuilderTest {

    private DataHash dataHash;
    private DataHash dataHash2;
    private DataHash dataHash3;

    private ImprintNode node;
    private ImprintNode node2;
    private ImprintNode node3;
    private MerkleTreeBuilder builder;

    @BeforeMethod
    public void setUp() throws Exception {
        dataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);
        dataHash2 = new DataHash(HashAlgorithm.SHA2_256, new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
        dataHash3 = new DataHash(HashAlgorithm.SHA2_256, new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2});

        node = new ImprintNode(dataHash);
        node2 = new ImprintNode(dataHash2);
        node3 = new ImprintNode(dataHash3, 1);
        this.builder = new MerkleTreeBuilder();
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Node can not be null")
    public void testAddMissingNode() throws Exception {
        builder.add((ImprintNode) null);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Nodes can not be null")
    public void testAddMissingNodes() throws Exception {
        builder.add((ImprintNode[]) null);
    }

    @Test(expectedExceptions = IllegalStateException.class, expectedExceptionsMessageRegExp = "Add leaf nodes before building a tree")
    public void testBuildTreeWithoutLeafs() throws Exception {
        builder.build();
    }

    @Test
    public void testCreateTreeWithOneLeaf() throws Exception {
        builder.add(node);
        ImprintNode root = builder.build();
        assertNotNull(root);
        assertEquals(new DataHash(root.getValue()), dataHash);
        assertEquals(root.getLevel(), 0);
        assertNull(root.getLeftChild());
        assertNull(root.getRightChild());
        assertNull(root.getParent());
    }

    @Test
    public void testCreateTreeWithMultipleLeafs() throws Exception {
        builder.add(node, node2, node2, node, node, node2, node2);
        ImprintNode root = builder.build();
        assertNotNull(root);
        assertEquals(root.getLevel(), 4);
    }

    @Test
    public void testCreateTreeWithMultipleDifferentSubtrees() throws Exception {
        builder.add(node, node, node3, node3, node3);
        ImprintNode root = builder.build();
        assertNotNull(root);
        assertEquals(root.getLevel(), 3);
    }


}