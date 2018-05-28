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

package com.guardtime.ksi.unisignature;

import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14_CALENDAR_HASH_CHAIN_DATA_HASH_MISMATCH;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14_CALENDAR_HASH_CHAIN_RIGHT_LINK_EXTRA;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14_CALENDAR_HASH_CHAIN_RIGHT_LINK_MISSING;
import static com.guardtime.ksi.TestUtil.loadSignature;
import static com.guardtime.ksi.unisignature.CalendarHashChainUtil.areRightLinksConsistent;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class CalendarHashChainUtilTest {
    private InMemoryKsiSignatureComponentFactory signatureComponentFactory;
    private CalendarHashChain calendarHashChain1;

    @BeforeMethod
    public void setUp() throws Exception {
        signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
        calendarHashChain1 = loadSignature(SIGNATURE_2017_03_14).getCalendarHashChain();
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "CalendarHashChain can not be null")
    public void testCalendarHashChainConsistency_firstChainNull_throwsNullPointerException() {
        areRightLinksConsistent(null, calendarHashChain1);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "CalendarHashChain can not be null")
    public void testCalendarHashChainConsistency_secondChainNull_throwsNullPointerException() {
        areRightLinksConsistent(calendarHashChain1, null);
    }

    @Test
    public void testCalendarHashChainConsistency_firstChainHasMoreRightLinks() throws Exception {
        boolean areChainsConsistent = areRightLinksConsistent(
                calendarHashChain1,
                readCalendarHashChainFromFile(SIGNATURE_2017_03_14_CALENDAR_HASH_CHAIN_RIGHT_LINK_MISSING));
        assertFalse(areChainsConsistent);
    }

    @Test
    public void testCalendarHashChainConsistency_secondChainHasMoreRightLinks() throws Exception {
        boolean areChainsConsistent = areRightLinksConsistent(
                calendarHashChain1,
                readCalendarHashChainFromFile(SIGNATURE_2017_03_14_CALENDAR_HASH_CHAIN_RIGHT_LINK_EXTRA));
        assertFalse(areChainsConsistent);
    }

    @Test
    public void testCalendarHashChainConsistency_calendarHashChainValueDifferent() throws Exception {
        boolean areChainsConsistent = areRightLinksConsistent(
                calendarHashChain1,
                readCalendarHashChainFromFile(SIGNATURE_2017_03_14_CALENDAR_HASH_CHAIN_DATA_HASH_MISMATCH));
        assertFalse(areChainsConsistent);
    }

    @Test
    public void testCalendarHashChainConsistency_Ok() throws Exception {
        boolean areChainsConsistent = areRightLinksConsistent(
                calendarHashChain1, loadSignature(EXTENDED_SIGNATURE_2017_03_14).getCalendarHashChain());
        assertTrue(areChainsConsistent);
    }

    private CalendarHashChain readCalendarHashChainFromFile(String calendarChainFileName) throws Exception {
        return signatureComponentFactory.createCalendarHashChain(loadTlv(calendarChainFileName));
    }
}