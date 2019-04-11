package com.guardtime.ksi.tree;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;

/**
 * A collection of miscellaneous, commonly used utility functions and constants.
 */
public final class Util {

    public static final HashAlgorithm DEFAULT_AGGREGATION_ALGORITHM = HashAlgorithm.getByName("DEFAULT");
    public static final int MAXIMUM_LEVEL = 255;

    private Util() {
    }

    /**
     * Calculates a data hash using the following formula: H(left||right||Util.encodeUnsignedLong(level)) where
     * H is a cryptographic hash function defined by {@code hashAlgorithm}.
     */
    public static DataHash hash(HashAlgorithm hashAlgorithm, byte[] left, byte[] right, long level) throws HashException {
        DataHasher hasher = new DataHasher(hashAlgorithm);
        hasher.addData(left).addData(right);
        hasher.addData(com.guardtime.ksi.util.Util.encodeUnsignedLong(level));
        return hasher.getHash();
    }

}
