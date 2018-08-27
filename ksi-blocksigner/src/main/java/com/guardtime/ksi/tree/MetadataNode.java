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

import static com.guardtime.ksi.util.Util.notNull;

/**
 * Represents metadata node.
 */
public class MetadataNode implements TreeNode {
    private final byte[] value;
    private final long level;
    TreeNode parent;

    MetadataNode(byte[] value, long level) {
        notNull(value, "Node value");
        this.value = value;
        this.level = level;
    }

    public TreeNode getParent() {
        return parent;
    }

    @Override
    public TreeNode getLeftChildNode() {
        return null;
    }

    @Override
    public TreeNode getRightChildNode() {
        return null;
    }

    @Override
    public boolean isLeft() {
        return false;
    }

    @Override
    public boolean isRoot() {
        return false;
    }

    @Override
    public boolean isLeaf() {
        return true;
    }

    public byte[] getValue() {
        return value;
    }

    public long getLevel() {
        return level;
    }
}
