package com.guardtime.ksi.service.ha.configuration;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.Future;

import java.util.Collection;

class HAConfFuture<T> implements Future<T> {

    private final Collection<Future<T>> confFutures;
    private final ConfResultSupplier<ConsolidationResult<T>> lastConsolidatedConfigurationSupplier;
    private ConsolidationResult<T> consolidationResult;

    HAConfFuture(Collection<Future<T>> confFutures, ConfResultSupplier<ConsolidationResult<T>> confResultSupplier) {
        this.confFutures = confFutures;
        this.lastConsolidatedConfigurationSupplier = confResultSupplier;
    }

    public synchronized T getResult() throws KSIException {
        if (consolidationResult == null) {
            waitForAllResponses();
            consolidationResult = lastConsolidatedConfigurationSupplier.get();
        }
        if (consolidationResult.wasSuccessful()) {
            return consolidationResult.getResult();
        }
        throw new KSIException("Configuration consolidation failed in HA service", consolidationResult.getException());
    }

    private void waitForAllResponses() {
        for (Future<T> confFuture : confFutures) {
            try {
                confFuture.getResult();
            } catch (Exception e) {
                // Configuration related exceptions will be handled in services themselves
            }
        }
    }

    public boolean isFinished() {
        if (consolidationResult == null) {
            for (Future<T> confFuture : confFutures) {
                if (!confFuture.isFinished()) {
                    return false;
                }
            }
        }
        return true;
    }

    interface ConfResultSupplier<T> {
        T get();
    }
}
