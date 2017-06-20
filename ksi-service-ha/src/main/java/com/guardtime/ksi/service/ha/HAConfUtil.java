/*
 * Copyright 2013-2017 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */
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
