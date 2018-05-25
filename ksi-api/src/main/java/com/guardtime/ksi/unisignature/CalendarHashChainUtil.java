/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

package com.guardtime.ksi.unisignature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;
import java.util.List;

import static com.guardtime.ksi.util.Util.notNull;

public final class CalendarHashChainUtil {

    private static final Logger logger = LoggerFactory.getLogger(CalendarHashChainUtil.class);

    /**
     * Checks consistency of two calendar hash chains: <ul>
     * <li>both calendar hash chains have same amount of right links</li>
     * <li>right chain links in the first chain are equal to the right chain links in the second chain</li>
     * </ul>
     *
     * @param calendarHashChain1 first calendar hash chain
     * @param calendarHashChain2 second calendar hash chain
     * @return true if both chains have same amount of right chain links and
     * all right chain link hash values are equal
     */
    public static boolean areCalendarHashChainRightLinksConsistent(CalendarHashChain calendarHashChain1,
                                                                   CalendarHashChain calendarHashChain2) {
        notNull(calendarHashChain1, "CalendarHashChain");
        notNull(calendarHashChain2, "CalendarHashChain");
        List<CalendarHashChainLink> rightLinks1 = getRightLinksFromCalendarHashChain(calendarHashChain1);
        List<CalendarHashChainLink> rightLinks2 = getRightLinksFromCalendarHashChain(calendarHashChain2);
        if (rightLinks1.size() != rightLinks2.size()) {
            logger.info("Calendar hash chains have different amount of right links: {} vs {}",
                    rightLinks1.size(), rightLinks2.size());
            return false;
        }

        for (int i = 0; i < rightLinks2.size(); i++) {
            CalendarHashChainLink link1 = rightLinks2.get(i);
            CalendarHashChainLink link2 = rightLinks1.get(i);
            if (!link1.getDataHash().equals(link2.getDataHash())) {
                logger.info("Calendar hash chain right links do not match at right link number {}", i + 1);
                return false;
            }
        }
        return true;
    }

    private static List<CalendarHashChainLink> getRightLinksFromCalendarHashChain(CalendarHashChain hashChain) {
        List<CalendarHashChainLink> rightLinks = new LinkedList<>();
        for (CalendarHashChainLink link : hashChain.getChainLinks()) {
            if (link.isRightLink()) {
                rightLinks.add(link);
            }
        }
        return rightLinks;
    }

    private CalendarHashChainUtil() {
    }
}
