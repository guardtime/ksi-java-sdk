/*
 * Copyright 2013-2017 Guardtime, Inc.
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

/**
 * Represents of a node in a binary tree.
 */
public interface TreeNode {

    /**
     * @return The value of the node, must always be present.
     */
    byte[] getValue();

    /**
     * @return The height of the node.
     */
    long getLevel();

    /**
     * @return The parent node. In case of root (head) node, null is returned.
     */
    TreeNode getParent();

    void setParent(TreeNode node);

    /**
     * @return Left child node. In case of leaf node, null is returned.
     */
    TreeNode getLeftChildNode();

    /**
     * @return Right child node. In case of leaf node, null is returned.
     */
    TreeNode getRightChildNode();

    /**
     * @return True, if this node is left child node.
     */
    boolean isLeft();

    /**
     * Helper to mark that the current node is left child node.
     *
     * @param b True, if the current node is left child node.
     */
    void setLeft(boolean b);

    /**
     * @return True, if current node is the root (head) node.
     */
    boolean isRoot();

    /**
     * @return True, if current node is the leaf node.
     */
    boolean isLeaf();
}
