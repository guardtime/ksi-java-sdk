package com.guardtime.ksi.service.ha;

import java.util.Date;

/**
 * Set of different utility methods used by HAClient
 */
class HAConfUtil {

    /**
     * Is value of b bigger than value of a. Returns true always if value of a is null.
     */
    static boolean isBigger(Long a, Long b) {
        return a == null || (b != null && b > a);
    }

    /**
     * Is value of b smaller than value of a. Returns true always if value of a is null.
     */
    static boolean isSmaller(Long a, Long b) {
        return a == null || (b != null && b < a);
    }

    /**
     * Is value of b after value of a. Returns true always if value of a is null.
     */
    static boolean isAfter(Date a, Date b) {
        return a == null || (b != null && b.after(a));
    }

    /**
     * Is value of b before value of a. Returns true always if value of a is null.
     */
    static boolean isBefore(Date a, Date b) {
        return a == null || (b != null && b.before(a));
    }

    /**
     * If a load balancing strategy is used then client can actually send more requests per second than it could
     * with single gateway because load is distributed. This method adjusts the max requests accordingly.
     */
    static Long adjustMaxRequests(int totalNumberOfClients, int numberOfClientsInOneRound, Long maxRequests) {
        if (maxRequests == null) {
            return null;
        }
        double percentageOfClientsTakingRequest = ((double) totalNumberOfClients) / numberOfClientsInOneRound;
        return (long) (maxRequests * percentageOfClientsTakingRequest);
    }
}
