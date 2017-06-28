package com.guardtime.ksi.service.ha;

import java.util.Collection;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;

/**
 * Task for invoking all the subclient tasks and returning the first successful one or throwing an exception if they all fail
 */
class ServiceCallsTask<T> implements Callable<T> {

    private final ExecutorService executorService;
    private final Collection<Callable<T>> serviceCallTasks;

    ServiceCallsTask(ExecutorService executorService, Collection<Callable<T>> serviceCallTasks) {
        this.executorService = executorService;
        this.serviceCallTasks = serviceCallTasks;
    }

    public T call() throws Exception {
        return executorService.invokeAny(serviceCallTasks);
    }
}
