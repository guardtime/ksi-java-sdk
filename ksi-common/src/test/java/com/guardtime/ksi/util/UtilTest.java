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
package com.guardtime.ksi.util;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;

public class UtilTest {

    @Test
    public void testConstructorIsPrivate() throws Exception {
        Constructor<Util> constructor = Util.class.getDeclaredConstructor();
        Assert.assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        constructor.newInstance();
    }

    @Test
    public void testLCM() {
        Assert.assertEquals(42, Util.lcm(21, 6));
        Assert.assertEquals(0, Util.lcm(0, 6));
        Assert.assertEquals(0, Util.lcm(21, 0));
    }

    @Test(expectedExceptions = ArithmeticException.class)
    public void testLCMOverflow() {
        Util.lcm(Integer.MAX_VALUE * 27 + 1, Integer.MAX_VALUE * 38 - 1);
    }

    @Test
    public void testCopyOf() {
        Assert.assertEquals(null, Util.copyOf(null));
        Assert.assertEquals("foobar".getBytes(), Util.copyOf("foobar".getBytes()));
    }

    @Test
    public void testCopyOfSection() {
        Assert.assertEquals("bar".getBytes(), Util.copyOf("foobar".getBytes(), 3, 3));
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testCopyOfSectionNull() {
        Assert.assertEquals("bar".getBytes(), Util.copyOf(null, 3, 3));
    }

    @Test(expectedExceptions = ArrayIndexOutOfBoundsException.class)
    public void testCopyOfSectionNegativeOffset() {
        Assert.assertEquals("bar".getBytes(), Util.copyOf("foobar".getBytes(), -3, 3));
    }

    @Test(expectedExceptions = ArrayIndexOutOfBoundsException.class)
    public void testCopyOfSectionOffsetLong() {
        Assert.assertEquals("bar".getBytes(), Util.copyOf("foobar".getBytes(), 30, 3));
    }

    @Test(expectedExceptions = ArrayIndexOutOfBoundsException.class)
    public void testCopyOfSectionNegativeLength() {
        Assert.assertEquals("bar".getBytes(), Util.copyOf("foobar".getBytes(), 3, -3));
    }

    @Test
    public void testToByteArray() {
        byte[] oneTwoThree = new byte[]{0, 123};
        Assert.assertEquals(Util.toByteArray((short) 123), oneTwoThree);
    }

    @Test
    public void testToShort() {
        byte[] oneTwoThree = new byte[]{0, 123};
        Assert.assertEquals(Util.toShort(oneTwoThree), (short) 123);
        byte[] oneTwoFour = new byte[]{0, 0, 0, 124};
        Assert.assertNotEquals(Util.toShort(oneTwoFour), (short) 124);
    }

    @Test
    public void testToInt() {
        byte[] oneTwoThree = new byte[]{0, 0, 0, 123};
        Assert.assertEquals(Util.toInt(oneTwoThree), 123);
    }

    @Test
    public void testCopyData() throws IOException {
        ByteArrayInputStream alfa = new ByteArrayInputStream("foobar".getBytes());
        ByteArrayOutputStream beta = new ByteArrayOutputStream();
        Util.copyData(alfa, beta);
        alfa.close();
        beta.close();
        Assert.assertEquals(beta.toString(), "foobar");

        alfa = new ByteArrayInputStream("foobar".getBytes());
        beta = new ByteArrayOutputStream();
        Util.copyData(alfa, beta, 3);
        alfa.close();
        beta.close();
        Assert.assertEquals(beta.toString(), "foo");

        alfa = new ByteArrayInputStream("foobar".getBytes());
        beta = new ByteArrayOutputStream();
        Util.copyData(alfa, beta, 3, 3);
        alfa.close();
        beta.close();
        Assert.assertEquals(beta.toString(), "foo");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testCopyDataFail() throws IOException {
        ByteArrayInputStream alfa = new ByteArrayInputStream("foobar".getBytes());
        ByteArrayOutputStream beta = new ByteArrayOutputStream();
        Util.copyData(alfa, beta, 3, 0);
        alfa.close();
        beta.close();
        Assert.assertEquals(beta.toString(), "foo");
    }

    @Test
    public void testEqualsBothNulls() {
        Assert.assertTrue(Util.equals(null, null));
    }

    @Test
    public void testEqualsOneNull() {
        Assert.assertFalse(Util.equals(null, new Object()));
        Assert.assertFalse(Util.equals(new Object(), null));
    }

    @Test
    public void testEqualsBothNotNull() {
        Assert.assertTrue(Util.equals("a_string", "a_string"));
    }

    @Test
    public void testEqualsIgnoreOrderBothNull() {
        Assert.assertTrue(Util.equalsIgnoreOrder(null,  null));
    }

    @Test
    public void testEqualsIgnoreOrderOneNull() {
        Assert.assertFalse(Util.equalsIgnoreOrder(null, Collections.emptyList()));
        Assert.assertFalse(Util.equalsIgnoreOrder(Collections.emptyList(), null));
    }

    @Test
    public void testEqualsIgnoreOrderSameContentsDifferentOrder() {
        Assert.assertTrue(Util.equalsIgnoreOrder(new ArrayList<String>(Arrays.asList("1", "2", "3")), new LinkedList<String>(Arrays.asList("2", "1", "3"))));
    }

    @Test
    public void testIntArrayContainsGivenKey() {
        Assert.assertTrue(Util.containsInt(new int[] {1, 2, 3, 4, 5}, 4));
    }

    @Test
    public void testIntArrayDoesNotContainsGivenKey() {
        Assert.assertFalse(Util.containsInt(new int[] {1, 2, 3, 4, 5}, 8));
    }

    @Test
    public void testToUrlOk() throws MalformedURLException {
        Assert.assertEquals(Util.toUrl("http://verify.guardtime.com"), new URL("http://verify.guardtime.com"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Malformed URL 'wrongURL'")
    public void testToUrlMalformedUrl() throws MalformedURLException {
        Util.toUrl("wrongURL");
    }

}
