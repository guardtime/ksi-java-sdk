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
    private AtomicReference<AssertionError> potentialFailure = new AtomicReference<AssertionError>();

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
