package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Verifies that RFC3161 record aggregation time equals to first aggregation chain aggregation time.
 */
public class Rfc3161RecordTimeRule extends BaseRule {

    private static final Logger logger = LoggerFactory.getLogger(AggregationHashChainTimeConsistencyRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        if (context.getRfc3161Record() != null) {
            Date rfc3161AggregationTime = context.getRfc3161Record().getAggregationTime();
            Date aggregationChainAggregationTime = context.getAggregationHashChains()[0].getAggregationTime();
            if (!rfc3161AggregationTime.equals(aggregationChainAggregationTime)) {
                logger.info("Aggregation hash chain and RFC 3161 aggregation time mismatch.");
                return VerificationResultCode.FAIL;
            }
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_02;
    }
}
