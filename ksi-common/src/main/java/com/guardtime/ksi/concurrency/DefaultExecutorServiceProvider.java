package com.guardtime.ksi.concurrency;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * SDK's different components use this class to get access to a common default {@link ExecutorService} if one has not been
 * provided to them.
 */
public class DefaultExecutorServiceProvider {

    private static ExecutorService executorService;

    /**
     * Used to get the default {@link ExecutorService} instance, which is a cached thread pool.
     */
    public synchronized static ExecutorService getExecutorService() {
        if (executorService == null) {
            executorService = Executors.newCachedThreadPool();
        }
        return executorService;
    }

}
