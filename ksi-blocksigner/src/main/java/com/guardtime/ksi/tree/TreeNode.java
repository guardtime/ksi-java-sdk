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

package com.guardtime.ksi.tree;

/**
 * This interface represents a node in a binary tree.
 */
public interface TreeNode {

    /**
     * Returns the value of the node. Must always be present.
     */
    byte[] getValue();

    /**
     * Returns the height of the node.
     */
    long getLevel();

    /**
     * Returns the parent node. In case of root (head) node the <i>null</i> is returned.
     */
    TreeNode getParent();

    void setParent(TreeNode node);

    /**
     * Returns left child node. In case of leaf node the <i>null</i> is returned.
     */
    TreeNode getLeftChild();

    /**
     * Returns right child node. In case of leaf node the <i>null</i> is returned.
     */
    TreeNode getRightChild();

    /**
     * Returns true is this node is left child node.
     */
    boolean isLeft();

    /**
     * Helper method to mark that the current node is left child node.
     */
    void setLeft(boolean b);

    /**
     * Returns true if current node is the root (head) node.
     */
    boolean isRoot();

    /**
     * Returns true if current node is the leaf node.
     */
    boolean isLeaf();
}
