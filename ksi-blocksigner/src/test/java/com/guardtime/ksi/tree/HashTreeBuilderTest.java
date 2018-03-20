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

import com.guardtime.ksi.hashing.DataHash;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH;
import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH_2;
import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH_3;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class HashTreeBuilderTest {

    private HashTreeBuilder builder;
    private ImprintNode node;
    private ImprintNode node2;
    private ImprintNode node3;


    @BeforeMethod
    public void setUp() {
        this.builder = new HashTreeBuilder();
        this.node = new ImprintNode(DATA_HASH);
        this.node2 = new ImprintNode(DATA_HASH_2);
        this.node3 = new ImprintNode(DATA_HASH_3, 1);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Node can not be null")
    public void testAddMissingNode() {
        builder.add((ImprintNode) null);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Nodes can not be null")
    public void testAddMissingNodes() {
        builder.add((ImprintNode[]) null);
    }

    @Test(expectedExceptions = IllegalStateException.class, expectedExceptionsMessageRegExp = "Add leaf nodes before building a tree")
    public void testBuildTreeWithoutLeafs() {
        builder.build();
    }

    @Test
    public void testCreateTreeWithOneLeaf() {
        builder.add(node);
        ImprintNode root = builder.build();
        assertNotNull(root);
        assertEquals(new DataHash(root.getValue()), DATA_HASH);
        assertEquals(root.getLevel(), 0);
        assertNull(root.getLeftChildNode());
        assertNull(root.getRightChildNode());
        assertNull(root.getParent());
    }

    @Test
    public void testCreateTreeWithMultipleLeafs() {
        builder.add(node, node2, node2, node, node, node2, node2);
        ImprintNode root = builder.build();
        assertNotNull(root);
        assertEquals(root.getLevel(), 3);
    }

    @Test
    public void testCreateTreeWithMultipleDifferentSubtrees() {
        builder.add(node, node, node3, node3, node3);
        ImprintNode root = builder.build();
        assertNotNull(root);
        assertEquals(root.getLevel(), 3);
    }

    @Test
    public void testCalculateTreeHeightWithOneLeaf() {
        assertEquals(builder.calculateHeight(node), 0);
    }

    @Test
    public void testCalculateTreeHeightWithMultipleLeafs() {
        builder.add(node, node2, node2, node, node, node2);
        assertEquals(builder.calculateHeight(node2), 3);
    }

    @Test
    public void testCalculateTreeHeightWithMultipleDifferentSubtrees() {
        builder.add(node, node, node3, node3);
        assertEquals(builder.calculateHeight(node3), 3);
    }

    @Test
    public void testCalculateTreeHeightInLoop() {
        long level = 0;
        //check first 14 levels
        for(int i = 0; i <= 16384; i++){
            if( level != builder.calculateHeight(node)){
                assertEquals((int)Math.pow(2, level), i);
                level = builder.calculateHeight(node);
            }
            builder.add(node);
        }
    }

}
