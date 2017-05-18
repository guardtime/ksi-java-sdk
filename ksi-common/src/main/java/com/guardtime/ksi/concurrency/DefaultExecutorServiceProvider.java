package com.guardtime.ksi.concurrency;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * SDK's different components use this class to get access to a common default {@link ExecutorService} if one has not been
 * provided to them.
 */
public class DefaultExecutorServiceProvider {

    private static final int MAXIMUM_POOL_SIZE = 10000;
    private static ExecutorService executorService;

    /**
     * Used to get the default {@link ExecutorService} instance, which is a cached thread pool.
     */
    public synchronized static ExecutorService getExecutorService() {
        if (executorService == null) {
            executorService = Executors.newCachedThreadPool();
            ((ThreadPoolExecutor) executorService).setMaximumPoolSize(MAXIMUM_POOL_SIZE);
        }
        return executorService;
    }

}
