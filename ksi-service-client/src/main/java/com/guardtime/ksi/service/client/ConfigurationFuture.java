package com.guardtime.ksi.service.client;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.Future;

import java.util.concurrent.ExecutionException;

public class ConfigurationFuture<T> implements Future<T> {

    private final java.util.concurrent.Future<T> requestFuture;
    private T result;

    ConfigurationFuture(java.util.concurrent.Future<T> requestFuture) {
        this.requestFuture = requestFuture;
    }

    public synchronized T getResult() throws KSIException {
        if (result != null) {
            return result;
        }
        waitForResponse();
        return result;
    }

    private void waitForResponse() throws KSIException {
        try {
            result = requestFuture.get();
        } catch (InterruptedException e) {
            throw new KSIClientException("Configuration update was interrupted", e);
        } catch (ExecutionException e) {
            throw new KSIClientException("Configuration update execution failed", e);
        }
    }

    public boolean isFinished() {
        return result != null || requestFuture.isDone();
    }
}
