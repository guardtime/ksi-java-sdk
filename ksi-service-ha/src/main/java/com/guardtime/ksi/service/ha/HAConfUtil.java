package com.guardtime.ksi.service.ha;

import java.util.Date;

/**
 * Set of different utility methods used by HAService
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

}
