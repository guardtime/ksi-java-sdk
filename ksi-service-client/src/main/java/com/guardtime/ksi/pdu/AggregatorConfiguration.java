package com.guardtime.ksi.pdu;

import com.guardtime.ksi.hashing.HashAlgorithm;

import java.util.List;

public interface AggregatorConfiguration {

    Long getMaximumLevel();

    HashAlgorithm getAggregationAlgorithm();

    Long getAggregationPeriod();

    Long getMaximumRequests();

    List<String> getParentUris();
}
