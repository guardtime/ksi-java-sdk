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
package com.guardtime.ksi.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.Arrays;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * JUnit test cases for the RFC 4684 base-X encoder/decoder classes.
 */
public class BaseTest {

    /**
     * Base-16 test vectors from RFC 4648.
     */
    private static final String[][] test16 = { { "", "" }, { "f", "66" }, { "fo", "666F" }, { "foo", "666F6F" },
            { "foob", "666F6F62" }, { "fooba", "666F6F6261" }, { "foobar", "666F6F626172" } };

    /**
     * Tests base-16 encoding.
     */
    @Test
    public void testEncode16() {
        for (int i = 0; i < test16.length; i++) {
            Assert.assertEquals(test16[i][1], Base16.encode(test16[i][0].getBytes()));
        }
        Assert.assertEquals(null, Base16.encode(null));
        Assert.assertEquals(null, Base16.encodeWithColons(null));
    }

    /**
     * Tests base-16 decoding.
     */
    @Test
    public void testDecode16() {
        for (int i = 0; i < test16.length; i++) {
            Assert.assertTrue(Arrays.equals(test16[i][0].getBytes(), Base16.decode(test16[i][1].toUpperCase())));
            Assert.assertTrue(Arrays.equals(test16[i][0].getBytes(), Base16.decode(test16[i][1].toLowerCase())));
        }
        Assert.assertEquals(null, Base16.decode(null));
    }

    /**
     * Base-32 test vectors from RFC 4648.
     */
    private static final String[][] test32 = { { "", "" }, { "f", "MY======" }, { "fo", "MZXQ====" },
            { "foo", "MZXW6===" }, { "foob", "MZXW6YQ=" }, { "fooba", "MZXW6YTB" }, { "foobar", "MZXW6YTBOI======" } };

    /**
     * Tests base-32 encoding.
     */
    @Test
    public void testEncode32() {
        for (int i = 0; i < test32.length; i++) {
            Assert.assertEquals(test32[i][1], Base32.encode(test32[i][0].getBytes()));
        }
        Assert.assertEquals(null, Base32.encode(null));
        Assert.assertEquals(null, Base32.encodeWithDashes(null));
    }

    /**
     * Tests base-32 decoding.
     */
    @Test
    public void testDecode32() {
        for (int i = 0; i < test32.length; i++) {
            Assert.assertTrue(Arrays.equals(test32[i][0].getBytes(), Base32.decode(test32[i][1].toUpperCase())));
            Assert.assertTrue(Arrays.equals(test32[i][0].getBytes(), Base32.decode(test32[i][1].toLowerCase())));
        }
        Assert.assertEquals(null, Base32.decode(null));
    }

    /**
     * Base-64 test vectors from RFC 4648.
     */
    private static final String[][] test64 = { { "", "" }, { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" },
            { "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" } };

    /**
     * Tests base-64 encoding.
     */
    @Test
    public void testEncode64() {
        for (int i = 0; i < test64.length; i++) {
            Assert.assertEquals(test64[i][1], Base64.encode(test64[i][0].getBytes()));
        }
        Assert.assertEquals(null, Base64.encode(null));
    }

    /**
     * Tests base-64 decoding.
     */
    @Test
    public void testDecode64() {
        for (int i = 0; i < test64.length; i++) {
            Assert.assertTrue(Arrays.equals(test64[i][0].getBytes(), Base64.decode(test64[i][1])));
        }
        Assert.assertEquals(null, Base64.decode(null));
    }

    @Test
    public void testConstructorIsPrivate() throws NoSuchMethodException, IllegalAccessException,
            InvocationTargetException, InstantiationException {
        Constructor<Base16> constructor16 = Base16.class.getDeclaredConstructor();
        Assert.assertTrue(Modifier.isPrivate(constructor16.getModifiers()));
        constructor16.setAccessible(true);
        constructor16.newInstance();

        Constructor<Base32> constructor32 = Base32.class.getDeclaredConstructor();
        Assert.assertTrue(Modifier.isPrivate(constructor32.getModifiers()));
        constructor32.setAccessible(true);
        constructor32.newInstance();

        Constructor<Base64> constructor64 = Base64.class.getDeclaredConstructor();
        Assert.assertTrue(Modifier.isPrivate(constructor64.getModifiers()));
        constructor64.setAccessible(true);
        constructor64.newInstance();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testBaseXWrongAlphabetLength() {
        new BaseX("012345789ABCDEF", false, ' ');
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testBaseXDelimiterInAlphabetLength() {
        new BaseX("0123456789ABCDEF", false, '5');
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testBaseXDuplicateCharactersInAlphabet() {
        new BaseX("0123455789ABCDEF", false, ' ');
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testBaseXEncodeNull() {
        BaseX inst = new BaseX("0123456789ABCDEF", false, ' ');
        inst.encode(null, " ", 2);
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testBaseXEncodeNullLong() {
        BaseX inst = new BaseX("0123456789ABCDEF", false, ' ');
        inst.encode(null, 1, 2, " ", 1);
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testBaseXDecodeNull() {
        BaseX inst = new BaseX("0123456789ABCDEF", false, ' ');
        inst.decode(null);
    }

    @Test(expectedExceptions = ArrayIndexOutOfBoundsException.class)
    public void testBaseXEncodeNegativeOffset() {
        BaseX inst = new BaseX("0123456789ABCDEF", false, ' ');
        inst.encode("foobar".getBytes(), -1, 2, " ", 1);
    }

    @Test(expectedExceptions = ArrayIndexOutOfBoundsException.class)
    public void testBaseXEncodeNegativeLength() {
        BaseX inst = new BaseX("0123456789ABCDEF", false, ' ');
        inst.encode("foobar".getBytes(), 1, -1, " ", 1);
    }

    @Test(expectedExceptions = ArrayIndexOutOfBoundsException.class)
    public void testBaseXEncodeOffsetTooLong() {
        BaseX inst = new BaseX("0123456789ABCDEF", false, ' ');
        inst.encode("foobar".getBytes(), 8, 2, " ", 1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testBaseXEncoindgSeparatorInAlphabet() {
        BaseX inst = new BaseX("0123456789ABCDEF", false, ' ');
        inst.encode("foobar".getBytes(), "1", 2);
    }

    /**
     * Tests base-X encoding.
     */
    @Test
    public void testEncodeX() {
        BaseX inst = new BaseX("0123456789ABCDEF", false, ' ');
        for (int i = 0; i < test16.length; i++) {
            Assert.assertEquals(test16[i][1], inst.encode(test16[i][0].getBytes(), "", 1).toString());
        }
    }

    private static final String[][] testXSeparated = { { "", "" }, { "f", "Zg-==" }, { "fo", "Zm-8=" }, { "foo", "Zm-9v" },
        { "foob", "Zm-9v-Yg-==" }, { "fooba", "Zm-9v-Ym-E=" }, { "foobar", "Zm-9v-Ym-Fy" } };

    /**
     * Tests base-X encoding with separators.
     */
    @Test
    public void testEncodeXSeparated() {
        BaseX inst = new BaseX("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", true, '=');
        for (int i = 0; i < testXSeparated.length; i++) {
            Assert.assertEquals(testXSeparated[i][1],
                    inst.encode(testXSeparated[i][0].getBytes(), 0, testXSeparated[i][0].length(), "-", 2).toString());
        }
    }


    /**
     * Tests base-X encoding with separators.
     */
    @Test
    public void testDecodeX() {
        BaseX inst = new BaseX("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", true, '=');
        for (int i = 0; i < test64.length; i++) {
            Assert.assertTrue(Arrays.equals(test64[i][0].getBytes(), inst.decode(test64[i][1])));
        }
        //test if the characters not in the alphabet range are ignored
        for (int i = 0; i < test64.length; i++) {
            Assert.assertTrue(Arrays.equals(test64[i][0].getBytes(), inst.decode(test64[i][1] + "*|")));
        }
    }

}
