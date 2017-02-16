package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * This rule checks that chain index of a aggregation hash chain is successor to it's parent aggregation hash chain index.
 */
public class AggregationHashChainIndexSuccessorRule extends BaseRule {

    private static final Logger logger = LoggerFactory.getLogger(AggregationHashChainIndexSuccessorRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        AggregationHashChain[] chains = context.getAggregationHashChains();
        List<Long> previousIndex = null;
        for (AggregationHashChain chain : chains) {
            List<Long> currentIndex = chain.getChainIndex();

            if (previousIndex != null) {
                logger.info("Current: {}; Previous index: {}", currentIndex, previousIndex);
                if (!isSuccessorIndex(previousIndex, currentIndex)) {
                    logger.info("Chain index is not the successor to the parent aggregation hash chain index. Invalid chain length. Chain index: {}; Parent chain index: {}", currentIndex, previousIndex);
                    return VerificationResultCode.FAIL;
                }
                if (!isPreviousIndex(previousIndex, currentIndex)) {
                    logger.info("Chain index is not the successor to the parent aggregation hash chain index. Invalid index value. Chain index: {}; Parent chain index: {}", currentIndex, previousIndex);
                    return VerificationResultCode.FAIL;
                }
            }
            previousIndex = currentIndex;
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_12;
    }

    private boolean isSuccessorIndex(List<Long> previousIndex, List<Long> currentIndex) {
        return previousIndex.size() - 1 == currentIndex.size();
    }

    private boolean isPreviousIndex(List<Long> previousIndex, List<Long> currentIndex) {
        for (int i = 0; i < currentIndex.size(); i++) {
            if (!currentIndex.get(i).equals(previousIndex.get(i))) {
                return false;
            }
        }
        return true;
    }

}
