/*
 * Copyright 2013-2015 Guardtime, Inc.
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

package com.guardtime.ksi.multisignature.file;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * Key object for holding aggregation hash chains. Aggregation hash chain key contains two parts. The first one is
 * aggregation time and the second one is list of location pointers.
 */
final class AggregationHashChainKey {

    private final Date aggregationTime;
    private final List<Long> locationPointers;

    AggregationHashChainKey(Date aggregationTime, List<Long> locationPointers) {
        this.aggregationTime = aggregationTime;
        this.locationPointers = locationPointers;
    }

    /**
     * Returns the list of keys based on location pointers.
     */
    public LinkedList<AggregationHashChainKey> getNextKeys() {
        int length = locationPointers.isEmpty() ? 0 : locationPointers.size() - 1;
        LinkedList<AggregationHashChainKey> keys = new LinkedList<AggregationHashChainKey>();
        for (int i = 0; i < length; i++) {
            keys.add(0, new AggregationHashChainKey(this.aggregationTime, locationPointers.subList(0, i + 1)));
        }
        return keys;
    }

    /**
     * Returns true when input key precedes current key.
     *
     * @param key
     *         key to check
     */
    public boolean precedes(AggregationHashChainKey key) {
        if (!key.aggregationTime.equals(aggregationTime)) {
            return false;
        }
        List<Long> indexes = key.locationPointers;
        if (indexes.size() >= locationPointers.size()) {
            return false;
        }
        for (int i = 0; i < indexes.size(); i++) {
            if (!indexes.get(i).equals(locationPointers.get(i))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AggregationHashChainKey that = (AggregationHashChainKey) o;

        if (aggregationTime != null ? !aggregationTime.equals(that.aggregationTime) : that.aggregationTime != null)
            return false;
        return !(locationPointers != null ? !locationPointers.equals(that.locationPointers) : that.locationPointers != null);

    }

    @Override
    public int hashCode() {
        int result = aggregationTime != null ? aggregationTime.hashCode() : 0;
        result = 31 * result + (locationPointers != null ? locationPointers.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        String s = "T=" + aggregationTime.getTime() + " I=";
        for (Long locationPointer : locationPointers) {
            s = s + locationPointer + ".";
        }

        return s.substring(0, s.length() - 1);
    }

    public int indexLength() {
        return locationPointers.size();
    }
}
