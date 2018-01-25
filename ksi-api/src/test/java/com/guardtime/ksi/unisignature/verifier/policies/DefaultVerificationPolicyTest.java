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

package com.guardtime.ksi.unisignature.verifier.policies;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class DefaultVerificationPolicyTest {

    @Test
    public void testCreateDefaultVerificationPolicy_Ok() throws Exception {
        DefaultVerificationPolicy policy = new DefaultVerificationPolicy();
        assertNotNull(policy.getFallbackPolicy());
        assertEquals(policy.getFallbackPolicy().getClass(), KeyBasedVerificationPolicy.class);
        assertEquals(policy.getName(), "Default verification policy");
        assertEquals(policy.getType(), "DEFAULT_POLICY");
    }

    @Test
    public void testSetFallbackForDefaultVerificationPolicy_Ok() throws Exception {
        DefaultVerificationPolicy policy = new DefaultVerificationPolicy();
        policy.setFallbackPolicy(new CalendarBasedVerificationPolicy());
        assertNotNull(policy.getFallbackPolicy());
        assertEquals(policy.getFallbackPolicy().getClass(), KeyBasedVerificationPolicy.class);
        assertNotNull(policy.getFallbackPolicy().getFallbackPolicy());
        assertEquals(policy.getFallbackPolicy().getFallbackPolicy().getClass(), CalendarBasedVerificationPolicy.class);
    }

    @Test
    public void testSetFallbackNullForDefaultVerificationPolicy_Ok() throws Exception {
        DefaultVerificationPolicy policy = new DefaultVerificationPolicy();
        policy.setFallbackPolicy(null);
        assertNotNull(policy.getFallbackPolicy());
        assertEquals(policy.getFallbackPolicy().getClass(), KeyBasedVerificationPolicy.class);
        assertNull(policy.getFallbackPolicy().getFallbackPolicy());
    }
}
