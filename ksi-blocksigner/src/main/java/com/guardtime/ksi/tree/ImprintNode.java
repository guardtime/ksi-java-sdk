/*
 * Copyright 2013-2016 Guardtime, Inc.
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

import static com.guardtime.ksi.util.Util.notNull;

import com.guardtime.ksi.hashing.DataHash;

/**
 * This class represents a hash tree node which every non-leaf node is labelled with the hash of the labels or values
 * (in case of leaves) of its child nodes.
 */
public class ImprintNode implements TreeNode {

    private final DataHash value;
    private final long level;

    private TreeNode parent;
    private TreeNode leftChild;
    private TreeNode rightChild;

    private boolean left = false;

    protected ImprintNode(ImprintNode node) {
        notNull(node, "ImprintNode");
        this.value = node.value;
        this.level = node.level;
        this.parent = node.parent;
        this.leftChild = node.leftChild;
        this.rightChild = node.rightChild;
    }

    public ImprintNode(DataHash value) {
        this(value, 0L);
    }

    public ImprintNode(DataHash value, long level) {
        notNull(value, "InputHash");
        this.value = value;
        this.level = level;
    }

    ImprintNode(TreeNode leftChild, TreeNode rightChild, DataHash value, long level) {
        notNull(leftChild, "LeftChild");
        notNull(rightChild, "RightChild");
        notNull(value, "DataHash");
        this.leftChild = leftChild;
        this.rightChild = rightChild;
        this.leftChild.setParent(this);
        this.leftChild.setLeft(true);
        this.rightChild.setParent(this);
        this.level = level;
        this.value = value;
    }

    public byte[] getValue() {
        return value.getImprint();
    }

    public TreeNode getParent() {
        return parent;
    }

    public void setParent(TreeNode node) {
        this.parent = node;
    }

    public TreeNode getLeftChildNode() {
        return leftChild;
    }

    public TreeNode getRightChildNode() {
        return rightChild;
    }

    public boolean isLeft() {
        return left;
    }

    public void setLeft(boolean b) {
        this.left = b;
    }

    public long getLevel() {
        return level;
    }

    public boolean isRoot() {
        return getParent() == null;
    }

    public boolean isLeaf() {
        return getLeftChildNode() == null && getRightChildNode() == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ImprintNode that = (ImprintNode) o;

        if (level != that.level) return false;
        return !(value != null ? !value.equals(that.value) : that.value != null);

    }

    @Override
    public int hashCode() {
        int result = value != null ? value.hashCode() : 0;
        result = 31 * result + (int) (level ^ (level >>> 32));
        return result;
    }

}
