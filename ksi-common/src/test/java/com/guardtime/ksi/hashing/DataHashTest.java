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
package com.guardtime.ksi.hashing;

import com.guardtime.ksi.util.Util;

import org.testng.Assert;
import org.testng.annotations.Test;

public class DataHashTest {

    private static final byte[] VALID_SHA256_CONTENT = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    private static final byte[] VALID_SHA256_IMPRINT = Util.join(new byte[] {1}, VALID_SHA256_CONTENT);

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp="Hash algorithm can not be null")
    public void testAlgorithmMissing() throws Exception {
        new DataHash(null, new byte[] {1});
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp="Hash value can not be null")
    public void testHashValueMissing() throws Exception {
        new DataHash(HashAlgorithm.SHA2_256, null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Hash size\\(1\\) does not match SHA-256 size\\(32\\)")
    public void testWrongLengthValue() throws Exception {
        new DataHash(HashAlgorithm.SHA2_256, new byte[] {1});
    }

    @Test
    public void testHashValue() throws Exception {
        DataHash dataHash = new DataHash(HashAlgorithm.SHA2_256, VALID_SHA256_CONTENT);
        Assert.assertEquals(dataHash.getAlgorithm(), HashAlgorithm.SHA2_256);
        Assert.assertEquals(dataHash.getImprint(), VALID_SHA256_IMPRINT);
        Assert.assertEquals(dataHash.getValue(), VALID_SHA256_CONTENT);

        DataHash newDataHash = new DataHash(HashAlgorithm.SHA2_256, VALID_SHA256_CONTENT);
        Assert.assertFalse(dataHash.equals(1));
        Assert.assertTrue(dataHash.equals(newDataHash));
        Assert.assertEquals(dataHash.hashCode(), newDataHash.hashCode());
    }

    @Test
    public void testIsDataHash() throws Exception {
        Assert.assertTrue(DataHash.isDataHash(VALID_SHA256_IMPRINT));
    }

    @Test
    public void testDataHashWithInvalidLength() throws Exception {
        Assert.assertFalse(DataHash.isDataHash(new byte[]{1,2}));
    }

    @Test
    public void testDataHashWithInvalidAlgorithmId() throws Exception {
        Assert.assertFalse(DataHash.isDataHash(new byte[]{-1,0,0}));
    }

    @Test
    public void testDataHashWithEmptyArray() throws Exception {
        Assert.assertFalse(DataHash.isDataHash(new byte[]{}));
    }
}
