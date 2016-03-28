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

package com.guardtime.ksi;


import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tree.ImprintNode;
import org.testng.annotations.BeforeMethod;

public abstract class AbstractBlockSignatureTest {

    protected DataHash dataHash;
    protected DataHash dataHash2;
    protected DataHash dataHash3;

    protected ImprintNode node;
    protected ImprintNode node2;
    protected ImprintNode node3;

    @BeforeMethod
    public void setUp() throws Exception {
        dataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);
        dataHash2 = new DataHash(HashAlgorithm.SHA2_256, new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
        dataHash3 = new DataHash(HashAlgorithm.SHA2_256, new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2});

        node = new ImprintNode(dataHash);
        node2 = new ImprintNode(dataHash2);
        node3 = new ImprintNode(dataHash3, 1);
    }

}
