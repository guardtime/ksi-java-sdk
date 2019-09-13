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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.util.Base16;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH;
import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH_2;
import static com.guardtime.ksi.AbstractBlockSignatureTest.DATA_HASH_3;
import static com.guardtime.ksi.AbstractBlockSignatureTest.IDENTITY_METADATA;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

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
    public void testCreateTreeWithMetadataLeaf() throws KSIException {
        builder.add(node, IDENTITY_METADATA);
        builder.add(node2);
        ImprintNode root = builder.build();
        assertNotNull(root);
        assertEquals(root.getLevel(), 2);
        assertTrue(node.getParent().getRightChildNode() instanceof MetadataNode);
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
    public void testCalculateTreeHeightWithOneLeafWithMetadata() throws KSIException {
        assertEquals(builder.calculateHeight(node, IDENTITY_METADATA), 1);
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
    
    @Test
    public void testRootHashFromFourLeaves() {

        //                  016587e3 2
        //          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
        //       01f50610 1                01f50610 1
        //     / ‾‾‾‾‾‾‾‾‾‾ \            / ‾‾‾‾‾‾‾‾‾‾ \
        //  01000000 0   01000000 0   01000000 0   01000000 0

    	byte[] imprint = Base16.decode("016587e39a15423f3918a862d0eab2723cf7f5d19c33c30beff407e100dedc1339");
    	for (byte i = 0; i < 4; ++i) {
    		builder.add(node);
    	}
    	assertEquals(builder.build().getValue(), imprint);
    }

    @Test
    public void testRootHashFromFiveLeaves() {

    	//                                01ddef63 3
    	//                     / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
        //                  016587e3 2                          \
        //          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                  \
        //       01f50610 1                01f50610 1             \
        //     / ‾‾‾‾‾‾‾‾‾‾ \            / ‾‾‾‾‾‾‾‾‾‾ \            \
        //  01000000 0   01000000 0   01000000 0   01000000 0   01000000 0

    	byte[] imprint = Base16.decode("01ddef6393b78840eb6335ee550ff81b7d806cfc7cfb6d32df8fbf69f2498f6db0");
    	for (byte i = 0; i < 5; ++i) {
    		builder.add(node);
    	}
    	assertEquals(builder.build().getValue(), imprint);
    }

    @Test
    public void testRootHashFromSixLeaves() {

    	//                                    01dc57fb 3
    	//                     / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
        //                  016587e3 2                                 \
        //          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                         \
        //       01f50610 1                01f50610 1                01f50610 1
        //     / ‾‾‾‾‾‾‾‾‾‾ \            / ‾‾‾‾‾‾‾‾‾‾ \            / ‾‾‾‾‾‾‾‾‾‾ \
        //  01000000 0   01000000 0   01000000 0   01000000 0   01000000 0   01000000 0

    	byte[] imprint = Base16.decode("01dc57fb3d7dc4c72adc777062b3374d8b2e74bc8395691bc810a1d324f7f11d02");
    	for (byte i = 0; i < 6; ++i) {
    		builder.add(node);
    	}
    	assertEquals(builder.build().getValue(), imprint);
    }

    @Test
    public void testRootHashFromSevenLeaves() {

    	//                                         01815d3e 3
    	//                     / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \ 
        //                  016587e3 2                                       01e4c3b3 2
        //          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                         / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
        //       01f50610 1                01f50610 1                01f50610 1             \
        //     / ‾‾‾‾‾‾‾‾‾‾ \            / ‾‾‾‾‾‾‾‾‾‾ \            / ‾‾‾‾‾‾‾‾‾‾ \            \
        //  01000000 0   01000000 0   01000000 0   01000000 0   01000000 0   01000000 0   01000000 0

    	byte[] imprint = Base16.decode("01815d3e92c2c2c99b650d849b950a7d0080bd9a5ed24a3dff4c9423b976b3fd5c");
    	for (byte i = 0; i < 7; ++i) {
    		builder.add(node);
    	}
    	assertEquals(builder.build().getValue(), imprint);
    }

    @Test
    public void testRootHashFromTwelveLeaves() {
        // Too big to draw...
    	byte[] imprint = Base16.decode("0148604b7e776b7d265457c835cb747fb24a6990c1fceadef19e74db5f4405ca01");
    	for (byte i = 0; i < 12; ++i) {
    		builder.add(node);
    	}
    	assertEquals(builder.build().getValue(), imprint);
    }

    @Test
    public void testRootHashFromThirteenLeaves() {
        // Too big to draw...
    	byte[] imprint = Base16.decode("01a8ede9ea0c5d5665e19f7b94ff3dc4e55f88dca6c71a1eba0c79b8ee2d3d81fd");
    	for (byte i = 0; i < 13; ++i) {
    		builder.add(node);
    	}
    	assertEquals(builder.build().getValue(), imprint);
    }
}
