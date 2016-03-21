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

import com.guardtime.ksi.exceptions.KSIException;

/**
 * This interface is used to build binary tree which every node in the tree has at most two children.
 * <p/>
 * To add new leafs to the tree methods {@link TreeBuilder#add(TreeNode)} or {@link TreeBuilder#add(TreeNode...)} can be
 * used. Note that this interface does not describe how leafs are processed and how binary tree is built. Several
 * different implementations can exist to support different type of trees. For example some implementation can sort
 * leafs and so break the order of the leafs.
 */
public interface TreeBuilder<N extends TreeNode> {

    /**
     * Adds a new leaf to the binary tree.
     *
     * @param node
     *         a leaf to add to the tree. must not be null.
     */
    void add(N node) throws KSIException;

    /**
     * Adds a new list of leafs to the binary tree
     *
     * @param nodes
     *         a list of leafs to be added to the tree. must not be null.
     */
    void add(N... nodes) throws KSIException;

    /**
     * Builds the binary tree and returns the root hash of the tree. {@link TreeNode#getLeftChild()} and/or {@link
     * TreeNode#getRightChild()} methods can be used for tree traversal.
     */
    N build() throws KSIException;

}
