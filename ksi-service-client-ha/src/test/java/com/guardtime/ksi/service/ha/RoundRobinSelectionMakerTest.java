/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.service.ha;

import org.testng.annotations.Test;

import java.util.Collection;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class RoundRobinSelectionMakerTest {

    @Test
    public void testOneObjectInSelection() throws Exception {
        Object o = new Object();
        RoundRobinSelectionMaker<Object> selectionMAker =
                new RoundRobinSelectionMaker<Object>(singletonList(o), 1);
        for (int i = 0; i < 10; i++) {
            Collection<Object> chosenSelection = selectionMAker.select();
            assertEquals(chosenSelection.size(), 1);
            assertTrue(chosenSelection.contains(o));
        }
    }

    @Test
    public void testTwoObjectsInSelectionOneInResult() throws Exception {
        Object o1 = new Object();
        Object o2 = new Object();
        RoundRobinSelectionMaker<Object> selectionMaker =
                new RoundRobinSelectionMaker<Object>(asList(o1, o2), 1);
        Collection<Object> chosenSelection = selectionMaker.select();
        assertEquals(chosenSelection.size(), 1);
        assertTrue(chosenSelection.contains(o1));
        chosenSelection = selectionMaker.select();
        assertEquals(chosenSelection.size(), 1);
        assertTrue(chosenSelection.contains(o2));
        chosenSelection = selectionMaker.select();
        assertEquals(chosenSelection.size(), 1);
        assertTrue(chosenSelection.contains(o1));
    }

    @Test
    public void testTwoObjectsInSelectionTwoInResult() throws Exception {
        Object o1 = new Object();
        Object o2 = new Object();
        RoundRobinSelectionMaker<Object> selectionMaker = new RoundRobinSelectionMaker<Object>(asList(o1, o2), 2);
        for (int i = 0; i < 10; i++) {
            Collection<Object> chosenSelection = selectionMaker.select();
            assertEquals(chosenSelection.size(), 2);
            assertTrue(chosenSelection.contains(o1));
            assertTrue(chosenSelection.contains(o2));
        }
    }

    @Test
    public void testFiveObjectsInSelectionThreeInResult() throws Exception {
        Object o1 = new Object();
        Object o2 = new Object();
        Object o3 = new Object();
        Object o4 = new Object();
        Object o5 = new Object();
        RoundRobinSelectionMaker<Object> selectionMaker = new RoundRobinSelectionMaker<Object>(
                asList(o1, o2, o3, o4, o5), 3);
        Collection<Object> chosenSelection = selectionMaker.select();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(o1));
        assertTrue(chosenSelection.contains(o2));
        assertTrue(chosenSelection.contains(o3));
        chosenSelection = selectionMaker.select();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(o2));
        assertTrue(chosenSelection.contains(o3));
        assertTrue(chosenSelection.contains(o4));
        chosenSelection = selectionMaker.select();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(o3));
        assertTrue(chosenSelection.contains(o4));
        assertTrue(chosenSelection.contains(o5));
        chosenSelection = selectionMaker.select();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(o4));
        assertTrue(chosenSelection.contains(o5));
        assertTrue(chosenSelection.contains(o1));
        chosenSelection = selectionMaker.select();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(o5));
        assertTrue(chosenSelection.contains(o1));
        assertTrue(chosenSelection.contains(o2));
        chosenSelection = selectionMaker.select();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(o1));
        assertTrue(chosenSelection.contains(o2));
        assertTrue(chosenSelection.contains(o3));
    }
}
