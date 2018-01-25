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
package com.guardtime.ksi;

import org.testng.Assert;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Helper class for testing asynchronous code. Helps to block the test until asynchronous code has finished and to keep track
 * of AssertionErrors thrown from non-main threads.
 */
public class AsyncContext {

    private CountDownLatch countDownLatch = new CountDownLatch(1);
    private AtomicReference<AssertionError> potentialFailure = new AtomicReference<>();

    public void succeed() {
        countDownLatch.countDown();
    }

    public void fail(AssertionError e) {
        potentialFailure.set(e);
        countDownLatch.countDown();
    }

    public void await() throws InterruptedException {
        int timeout = 4;
        if (!countDownLatch.await(timeout, TimeUnit.SECONDS)) {
            Assert.fail("Test timed out after " + timeout + " seconds.");
        }
        AssertionError assertionError = potentialFailure.get();
        if (assertionError != null) {
            throw assertionError;
        }
    }
}
