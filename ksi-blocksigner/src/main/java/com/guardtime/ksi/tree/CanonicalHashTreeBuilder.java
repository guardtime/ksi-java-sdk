/*
 * Copyright 2013-2020 Guardtime, Inc.
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

import com.guardtime.ksi.hashing.HashAlgorithm;

import java.util.LinkedList;

/**
 * Hash tree (aka Merkle tree) builder implementation.
 * <p>Hash tree is a tree in which every non-leaf node
 * is labelled with the hash of the labels or values (in case of leaves) of its child nodes.
 * </p>
 * <p>
 * Note that {@link CanonicalHashTreeBuilder} works only with {@link ImprintNode} objects.
 * Canonical trees are built as follows:
 *  <ul>
 *      <li>The leaf nodes are laid out from left to right</li>
 *      <li>The leaf nodes are collected into perfect binary trees from left to right making each tree as big as
 *      possible using the leaves still available </li>
 *      <li>The perfect trees are merged into a single tree from right to left which means joining the two smallest
 *      trees on each step</li>
 *  </ul>
 * </p>
 * This builder can not be used multiple times.
 */
public class CanonicalHashTreeBuilder extends HashTreeBuilder {

    public CanonicalHashTreeBuilder(HashAlgorithm algorithm) {
        super(algorithm);
    }

    public CanonicalHashTreeBuilder() {
        super();
    }

    @Override
    protected ImprintNode getRootNode(LinkedList<ImprintNode> heads) {
        ImprintNode previous = heads.getLast();
        if (heads.size() > 1) {
            for (int i = heads.size() - 2; i > -1; i--) {
                ImprintNode current = heads.get(i);
                previous = aggregate(current, previous);
            }
        }
        return previous;
    }
}
