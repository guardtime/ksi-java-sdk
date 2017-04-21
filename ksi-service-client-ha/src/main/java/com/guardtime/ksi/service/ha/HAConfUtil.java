package com.guardtime.ksi.service.ha;

import java.util.Date;

public class HAConfUtil {

    public static boolean isBigger(Long a, Long b) {
        return a == null || (b != null && b > a);
    }

    public static boolean isSmaller(Long a, Long b) {
        return a == null || (b != null && b < a);
    }

    public static boolean isAfter(Date a, Date b) {
        return a == null || (b != null && b.after(a));
    }

    public static boolean isBefore(Date a, Date b) {
        return a == null || (b != null && b.before(a));
    }

    /**
     * If a load balancing strategy is used then client can actually send more requests per second than it could
     * with single gateway because load is distributed. This method adjusts the max requests accordingly.
     */
    public static Long adjustMaxRequests(int totalNumberOfClients, int numberOfClientsInOneRound, Long maxRequests) {
        if (maxRequests == null) {
            return null;
        }
        double percentageOfClientsTakingRequest = ((double) totalNumberOfClients) / numberOfClientsInOneRound;
        return (long) (maxRequests * percentageOfClientsTakingRequest);
    }
}
